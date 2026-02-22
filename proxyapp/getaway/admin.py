from django.contrib import admin
from django.utils.timezone import localtime
from .models import AccessLog

@admin.register(AccessLog)
class AccessLogAdmin(admin.ModelAdmin):
    list_display = ("user", "domain", "url", "local_created_at")
    actions = ("delete_selected_logs",)

    def local_created_at(self, obj):
        return localtime(obj.created_at).strftime("%d-%m-%Y %H:%M:%S")

    local_created_at.short_description = "Date"

    @admin.action(description="Delete selected access logs")
    def delete_selected_logs(self, request, queryset):
        queryset.delete()

    def get_actions(self, request):
        actions = super().get_actions(request)
        if not request.user.is_superuser:
            actions.pop("delete_selected_logs", None)
        return actions

    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser
