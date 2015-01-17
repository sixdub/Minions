from django.conf.urls import patterns, include, url
from django.contrib import admin

admin.site.site_header="Scanner Admin"

urlpatterns = patterns('',
    # Examples:
    url(r'^admin/', include(admin.site.urls), name='admin'),
    url(r'^', include('scans.urls')),
)
