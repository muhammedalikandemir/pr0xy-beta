from django.http import HttpResponse
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from urllib.parse import parse_qs, quote, unquote, urljoin, urlparse
import requests
import os
import re
from .models import AccessLog
from django.utils import timezone
from datetime import timedelta
from django.conf import settings

def normalize_host(host):
    host = (host or "").lower().strip()
    if host.startswith("www."):
        return host[4:]
    return host


def host_matches_rule(host, rule):
    host = normalize_host(host)
    rule = normalize_host(rule)
    if not host or not rule:
        return False
    if rule.startswith("*."):
        rule = rule[2:]
    return host == rule or host.endswith(f".{rule}")


def is_allowed_host(host, rules):
    return any(host_matches_rule(host, rule) for rule in rules)


def extract_hostname(host_or_url):
    if not host_or_url:
        return ""
    candidate = host_or_url.strip()
    if "://" in candidate:
        parsed = urlparse(candidate)
    else:
        parsed = urlparse(f"//{candidate}")
    return normalize_host(parsed.hostname)


def parse_csv_env(name):
    return [h.strip() for h in os.environ.get(name, "").split(",") if h.strip()]


def get_tls_verify_setting():
    ca_bundle = os.environ.get("EZPROXY_CA_BUNDLE", "").strip()
    if ca_bundle:
        return ca_bundle

    verify_env = os.environ.get("EZPROXY_TLS_VERIFY", "").strip().lower()
    if verify_env in {"0", "false", "no", "off"}:
        return False
    return True


def allow_insecure_tls_fallback():
    """
    In local/debug mode, allow one insecure retry when TLS verification fails.
    Can be overridden with EZPROXY_ALLOW_INSECURE_FALLBACK.
    """
    value = os.environ.get("EZPROXY_ALLOW_INSECURE_FALLBACK", "").strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return bool(getattr(settings, "DEBUG", False))


def normalize_allowed_rule(value):
    value = (value or "").strip()
    if not value:
        return ""

    wildcard = value.startswith("*.")
    if wildcard:
        value = value[2:]

    host = extract_hostname(value)
    if not host:
        return ""
    return f"*.{host}" if wildcard else host


def build_quick_route_url():
    host = os.environ.get("EZPROXY_PUBLIC_SITE_HOST", "").strip()
    if not host:
        return ""
    if host.startswith(("http://", "https://")):
        return host
    return f"https://{host}"


def to_proxy_url(target_url):
    return f"/proxy/?url={quote(target_url, safe='')}"


def resolve_target_url(raw_url):
    raw_url = (raw_url or "").strip()
    if not raw_url:
        return ""
    if "://" not in raw_url:
        raw_url = f"https://{raw_url}"
    return raw_url


def is_passthrough_url(value):
    lowered = (value or "").strip().lower()
    return (
        not lowered
        or lowered.startswith("#")
        or lowered.startswith("javascript:")
        or lowered.startswith("mailto:")
        or lowered.startswith("tel:")
        or lowered.startswith("data:")
    )


def should_keep_direct_asset_url(absolute_url):
    return False


def rewrite_srcset(srcset_value, base_url, proxy_host=""):
    candidates = []
    for item in srcset_value.split(","):
        item = item.strip()
        if not item:
            continue
        parts = item.split()
        raw = parts[0]
        if not is_passthrough_url(raw):
            absolute = urljoin(base_url, raw)
            if absolute.startswith(("http://", "https://")):
                if should_keep_direct_asset_url(absolute):
                    parts[0] = absolute
                else:
                    parts[0] = to_proxy_url(absolute)
        candidates.append(" ".join(parts))
    return ", ".join(candidates)


def rewrite_html_for_proxy(html, base_url, proxy_host=""):
    attr_pattern = re.compile(
        r'(?P<attr>\b(?:href|src|action|poster)\s*=\s*)(?P<q>["\'])(?P<val>.*?)(?P=q)',
        flags=re.IGNORECASE | re.DOTALL,
    )
    srcset_pattern = re.compile(
        r'(?P<attr>\bsrcset\s*=\s*)(?P<q>["\'])(?P<val>.*?)(?P=q)',
        flags=re.IGNORECASE | re.DOTALL,
    )
    refresh_pattern = re.compile(
        r'(?P<attr>\bcontent\s*=\s*)(?P<q>["\'])(?P<val>[^"\']*\burl=)(?P<url>[^"\']+)(?P=q)',
        flags=re.IGNORECASE,
    )

    def replace_attr(match):
        current_val = match.group("val").strip()
        if is_passthrough_url(current_val):
            return match.group(0)
        absolute = urljoin(base_url, current_val)
        if not absolute.startswith(("http://", "https://")):
            return match.group(0)
        if should_keep_direct_asset_url(absolute):
            return f'{match.group("attr")}{match.group("q")}{absolute}{match.group("q")}'
        return f'{match.group("attr")}{match.group("q")}{to_proxy_url(absolute)}{match.group("q")}'

    def replace_srcset(match):
        current_val = match.group("val").strip()
        if not current_val:
            return match.group(0)
        rewritten = rewrite_srcset(current_val, base_url, proxy_host=proxy_host)
        return f'{match.group("attr")}{match.group("q")}{rewritten}{match.group("q")}'

    def replace_refresh(match):
        current_url = match.group("url").strip()
        if is_passthrough_url(current_url):
            return match.group(0)
        absolute = urljoin(base_url, current_url)
        if not absolute.startswith(("http://", "https://")):
            return match.group(0)
        return (
            f'{match.group("attr")}{match.group("q")}'
            f'{match.group("val")}{to_proxy_url(absolute)}{match.group("q")}'
        )

    html = attr_pattern.sub(replace_attr, html)
    html = srcset_pattern.sub(replace_srcset, html)
    html = refresh_pattern.sub(replace_refresh, html)
    return html


def rewrite_css_for_proxy(css, base_url, proxy_host=""):
    url_pattern = re.compile(
        r"url\(\s*(?P<q>['\"]?)(?P<val>[^)'\"]+?)(?P=q)\s*\)",
        flags=re.IGNORECASE,
    )
    import_pattern = re.compile(
        r"@import\s+(?P<q>['\"])(?P<val>[^'\"]+)(?P=q)",
        flags=re.IGNORECASE,
    )

    def rewrite_reference(raw_value):
        current_val = (raw_value or "").strip()
        if (
            is_passthrough_url(current_val)
            or current_val.startswith("/proxy/?url=")
            or current_val.startswith("about:")
        ):
            return current_val
        absolute = urljoin(base_url, current_val)
        if not absolute.startswith(("http://", "https://")):
            return current_val
        if should_keep_direct_asset_url(absolute):
            return absolute
        return to_proxy_url(absolute)

    def replace_url(match):
        rewritten = rewrite_reference(match.group("val"))
        return f"url({match.group('q')}{rewritten}{match.group('q')})"

    def replace_import(match):
        rewritten = rewrite_reference(match.group("val"))
        return f"@import {match.group('q')}{rewritten}{match.group('q')}"

    css = url_pattern.sub(replace_url, css)
    css = import_pattern.sub(replace_import, css)
    return css


def get_proxy_referer(request):
    referer = request.META.get("HTTP_REFERER", "")
    if not referer:
        return ""
    parsed = urlparse(referer)
    if parsed.path != "/proxy/":
        return ""
    upstream = parse_qs(parsed.query).get("url", [""])[0]
    return unquote(upstream) if upstream else ""


def get_upstream_headers(request, target_host):
    headers = {
        "User-Agent": request.META.get("HTTP_USER_AGENT", ""),
        "Accept": request.META.get("HTTP_ACCEPT", "*/*"),
        "Accept-Language": request.META.get("HTTP_ACCEPT_LANGUAGE", ""),
    }
    if request.META.get("CONTENT_TYPE"):
        headers["Content-Type"] = request.META["CONTENT_TYPE"]
    upstream_referer = get_proxy_referer(request)
    if upstream_referer:
        headers["Referer"] = upstream_referer
    headers["Host"] = target_host
    return {k: v for k, v in headers.items() if v}


def get_upstream_payload(request):
    method = request.method.upper()
    if method in {"GET", "HEAD", "OPTIONS"}:
        return None, None

    content_type = (request.META.get("CONTENT_TYPE", "") or "").lower()
    if "multipart/form-data" in content_type:
        return request.POST, request.FILES
    if "application/x-www-form-urlencoded" in content_type:
        return request.POST, None
    return request.body, None


def update_session_cookies(request, host, response):
    store = request.session.get("proxy_cookies", {})
    host_cookies = store.get(host, {})
    host_cookies.update(response.cookies.get_dict())
    store[host] = host_cookies
    request.session["proxy_cookies"] = store
    request.session.modified = True


def home(request):
    return render(
        request,
        "home.html",
        {"public_site_url": build_quick_route_url()},
    )


@csrf_exempt
@login_required
def proxy(request):
    cutoff = timezone.now() - timedelta(days=30)
    AccessLog.objects.filter(created_at__lt=cutoff).delete()
    url = resolve_target_url(request.GET.get("url", ""))

    if not url:
        return HttpResponse("URL parametresi yok", status=400)

    parsed = urlparse(url)
    host = parsed.hostname

    if not host:
        return HttpResponse("Geçersiz URL", status=400)

    if parsed.scheme not in ("http", "https"):
        return HttpResponse("Sadece http/https desteklenir", status=400)

    normalized_host = normalize_host(host)

    print("LOG:", request.user, url)

    payload, files = get_upstream_payload(request)
    stored_cookies = request.session.get("proxy_cookies", {}).get(normalized_host, {})

    verify_setting = get_tls_verify_setting()

    def send_upstream(verify_value):
        return requests.request(
            method=request.method.upper(),
            url=url,
            data=payload,
            files=files,
            headers=get_upstream_headers(request, parsed.netloc),
            cookies=stored_cookies,
            allow_redirects=False,
            timeout=15,
            verify=verify_value,
        )

    try:
        try:
            r = send_upstream(verify_setting)
        except requests.exceptions.SSLError as ssl_err:
            if verify_setting is True and allow_insecure_tls_fallback():
                r = send_upstream(False)
            else:
                raise ssl_err

        if 200 <= r.status_code < 400:
            AccessLog.objects.create(
                user=request.user,
                url=url,
                domain=normalized_host,
            )

        update_session_cookies(request, normalized_host, r)

        if 300 <= r.status_code < 400 and r.headers.get("Location"):
            upstream_location = urljoin(url, r.headers["Location"])
            redirect = HttpResponse(status=r.status_code)
            redirect["Location"] = to_proxy_url(upstream_location)
            return redirect

        content_type = r.headers.get("Content-Type", "text/html")

        if "text/html" in content_type.lower():
            html = rewrite_html_for_proxy(r.text, r.url, proxy_host=request.get_host())
            return HttpResponse(html, content_type=content_type)
        if "text/css" in content_type.lower():
            css = rewrite_css_for_proxy(r.text, r.url, proxy_host=request.get_host())
            return HttpResponse(css, status=r.status_code, content_type=content_type)

        response = HttpResponse(r.content, status=r.status_code, content_type=content_type)
        if r.headers.get("Content-Disposition"):
            response["Content-Disposition"] = r.headers["Content-Disposition"]
        if r.headers.get("Cache-Control"):
            response["Cache-Control"] = r.headers["Cache-Control"]
        return response
    except requests.exceptions.SSLError as e:
        return HttpResponse(
            "TLS/SSL dogrulamasi basarisiz. "
            "Ortamda ozel bir sertifika zinciri varsa EZPROXY_CA_BUNDLE ayarlayin. "
            f"Detay: {e}",
            status=502,
        )
    except Exception as e:
        return HttpResponse("Hata oluştu: " + str(e), status=500)
