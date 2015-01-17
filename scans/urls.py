from django.conf.urls import patterns, url
from scans import views

urlpatterns=patterns('',
	url(r'^$',views.index, name='index'),
	url(r'^new/$',views.new_scan, name='new_scan'),
	url(r'^serverctl/$', views.server_control, name="server_control"),
	url(r'^serverctl/action/(?P<action_id>\d+)/$', views.server_action, name="server_action"),
	url(r'^(?P<scan_id>\d+)/$', views.scan_detail, name='scan_detail'),
	url(r'^(?P<scan_id>\d+)/delete$', views.scan_delete, name='scan_delete'),
	url(r'^(?P<download_id>\d+)/download/$', views.scan_download, name='scan_download'),
	url(r'^searchresults/$', views.search_results, name="search_results"),
	url(r'^scanprofiles/$', views.scan_profiles, name="scan_profiles"),
	url(r'^scanprofiles/new/$', views.new_scan_profile, name="new_scan_profile"),
	url(r'^scanprofiles/(?P<profile_id>\d+)/delete$', views.delete_profile, name="delete_profile"),

	#/login and /logout
    url(r'^login/$', 'django.contrib.auth.views.login', name="login"),
    url(r'^logout/$', 'django.contrib.auth.views.logout', name="logout"),

	#Ajax Stuff
	url(r'^a/scans/', views.ajax_scan_list, name="a_scan_list"),
	url(r'^a/serverat/', views.ajax_server_at, name="a_server_at"),
	url(r'^a/serveroutput/', views.ajax_server_output, name="a_server_output"),
	url(r'^a/serverjobs/', views.ajax_server_jobs, name="a_server_jobs"),
	url(r'^a/serverlog/', views.ajax_server_log, name="a_server_log"),

)
