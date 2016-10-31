"""cve_webapp URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.10/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url
from django.contrib import admin
from global_app import views

urlpatterns = [
    url(r'^$', views.index, name='home'),
    url(r'^get_year/(?P<year>[0-9]{4})$', views.SelectYear.as_view(), name='get_year'),
    url(r'^get_json/(?P<year>[0-9]{4})$', views.GetJSON.as_view(), name='get_json'),

    url(r'^get_detail/(?P<cv_id>.*)$', views.GetDetail.as_view(), name='get_detail'),
    url(r'^modified$', views.getModified.as_view(), name='get_modified'),
    url(r'^recent$', views.getRecent.as_view(), name='get_recent')
]
