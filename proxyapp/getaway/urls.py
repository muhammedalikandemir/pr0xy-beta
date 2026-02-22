from django.urls import path
from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("proxy/", views.proxy, name="proxy"),
]
