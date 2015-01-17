from django.conf import settings
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect, HttpResponse, HttpResponseNotFound
from django.core.urlresolvers import reverse
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import Q
from django.core.servers.basehttp import FileWrapper
from django.core.files import File
from scans.models import Scan, Scan_Profile
from scans.forms import ScanForm, ScanProfileForm
import os, tempfile, zipfile, StringIO, sys, subprocess
from datetime import datetime
from django.utils.timezone import utc

#define some static variables to be used later
login_page=settings.LOGIN_PAGE
project_dir = settings.PROJECT_PATH
module_dir=os.path.join(project_dir,"scan_engine")

#### PRIMARY VIEWS
#Main Page
@login_required(login_url=login_page)
def index(request):
	return render(request, 'scans/index.html')

#Delete a scan
@login_required(login_url=login_page)
def scan_delete(request, scan_id):
	scan = get_object_or_404(Scan,pk=scan_id)
	scan.delete()
	return HttpResponseRedirect('/')

#See all scan profiles
@login_required(login_url=login_page)
def scan_profiles(request):
	profile_list = Scan_Profile.objects.all()
	context={'profiles':profile_list}
	return render(request, 'scans/scan_profiles.html', context)

#delete a scan profile
@login_required(login_url=login_page)
def delete_profile(request, profile_id):
	profile = get_object_or_404(Scan_Profile,pk=profile_id)
	profile.delete()
	return HttpResponseRedirect(reverse('scan_profiles', current_app='scans'))

#Create a scan profile. Process a form
@login_required(login_url=login_page)
def new_scan_profile(request):
	if request.method == 'POST':
		form = ScanProfileForm(request.POST)
		if form.is_valid():
			cd = form.cleaned_data
			profilename = cd['name']
			profilecmd = cd['cmdline']
			r_user = request.user
			if profilename and r_user and profilecmd:
				s = Scan_Profile(name=profilename, author=r_user, cmdline=profilecmd)
				s.save()
			else:
				return HttpResponseNotFound('<h1>Incomplete Data</h1>')
			return HttpResponseRedirect('/scanprofiles')
	else:
		form = ScanProfileForm()
	return render(request, 'scans/new_scan_profile.html', {'form': form})

#Get details about a scan. Do that by opening a .nmap file
@login_required(login_url=login_page)
def scan_detail(request,scan_id):
	scan_list = get_object_or_404(Scan,pk=scan_id)
	d = ''
	path=os.path.join(module_dir,"nmap_results/processed/"+scan_id+".nmap")
	if os.path.isfile(path):
		with open(path, "r") as f:
			d = f.read()
	nmap_cmd="nmap "+scan_list.profile.cmdline+" "+scan_list.hosts+" -oA "+str(scan_list.id)
	context={'scans':scan_list, 'data':d, 'cmd':nmap_cmd,}
	return render(request, 'scans/scan_detail.html', context)

#Provide control to the user
@login_required(login_url=login_page)
def server_control(request):
	#get the path for infromation
	output = ''
	with open(os.path.join(module_dir, "current_output"), 'r') as infi:
		output = infi.read()

	#read the log
	log=""
	linenum=0
	for line in reversed(open(os.path.join(module_dir, "log")).readlines()):
		log+=line
		linenum+=1
		if linenum > 10:
			break

	#read the jobs
	jobs=""
	linenum=0
	for line in reversed(open(os.path.join(module_dir,"jobs")).readlines()):
		jobs+=line
		linenum+=1
		if linenum > 10:
			break
	context={'output':output, "log":log, "jobs":jobs}
	return render(request, 'scans/server_control.html', context)

#handle the control buttons. Lots of OS.system in here. 
@login_required(login_url=login_page)
def server_action(request, action_id):
	if request.user.is_superuser:
		#clear output
		if action_id=="1": 
			os.system('> ' + os.path.join(module_dir,"current_output"))
			return HttpResponse("Output Cleared")
		#Clear log
		elif action_id=="2":
			os.system('> ' + os.path.join(module_dir,'log'))
			return HttpResponse("Log Cleared")
		#clear jobs 
		elif action_id=="3":
			os.system('> ' + os.path.join(module_dir,'jobs'))
			os.system('> '+os.path.join(module_dir,'jobs.dnmaptrace'))
			return HttpResponse("Jobs Cleared")
		#clear scan output
		elif action_id=="4":
			os.system('rm -rf '+os.path.join(module_dir,'nmap_results/processed/*'))
			Scan.objects.all().delete()
			return HttpResponse("Scan Output Cleared")
		#clear all 
		elif action_id=="5":
			os.system('> '+os.path.join(module_dir,'current_output'))
			os.system('> '+os.path.join(module_dir,'log'))
			os.system('> '+os.path.join(module_dir,'jobs'))
			os.system('> '+os.path.join(module_dir,'jobs.dnmaptrace'))
			os.system('rm -rf '+os.path.join(module_dir,'nmap_results/processed/*'))
			Scan.objects.all().delete()
			return HttpResponse("All Cleared")
		#start server
		elif action_id=="6":
			os.system("(python %s/dnmap_server.py -P %s/server.pem -c %s/ca.pem -p 8001 -f %s/jobs -L %s/log -S %s/db.sqlite3) &"%(module_dir, module_dir, module_dir, module_dir, module_dir, project_dir))
			return HttpResponse("Server Started")
		#kill server
		elif action_id=="7":
			os.system('pkill -f "dnmap"')
			return HttpResponse("Server Killed")
		else:
			return HttpResponse("Error")
	else:
		return HttpResponse("You need to be an admin!")

@login_required(login_url=login_page)
#return search results
def search_results(request):	
	match = ''
	q = request.GET.get('q', "")
	if q:
		match=Scan.objects.filter(Q(name__icontains=q)|Q(summary__icontains=q)|Q(hosts__icontains=q))
	context={"search":match}
	return render(request, 'scans/search_results.html', context)

#process a new scan form
@login_required(login_url=login_page)
def new_scan(request):
	if request.method == 'POST':
		form = ScanForm(request.POST)
		#validate the form
		if form.is_valid():
			cd = form.cleaned_data
			hlist=""
			hostlist = cd['hosts']
			for line in hostlist.split("\n"): #if your hosts field can have multiple lines, you can remove this
				elems = line.split(",")#creates an array from comma separated values
				if line:
					for el in elems:
						hlist+=el.rstrip()+" "
			#get all of the fields including the split up hosts
			shosts=hlist.rstrip(',')
			name = cd['name']
			scantype = cd['profile']
			r_user= request.user
			profilecmd=scantype.cmdline
			nmap_cmd="nmap "+profilecmd+" "+shosts
			rundatetime = cd['time']

			#assuming all fields are set
			if nmap_cmd and r_user and name and shosts and scantype:
				#input the scan into the DB
				s = Scan(profile=scantype, user=r_user, name=name, hosts=shosts)
				s.save()

				#create the nmap command and add to the jobs file
				nmap_cmd_total = nmap_cmd+" -oA %s" %(s.id)
				nowtime = datetime.utcnow().replace(tzinfo=utc)
				jobspath = "%s/scan_engine/jobs"%project_dir

				#decide if this is a future job, if so, schedule it
				if rundatetime > nowtime:
					atcmd= "echo echo %s \>\> %s | at %s" %(nmap_cmd_total, jobspath, rundatetime.strftime("%I:%M %p %m/%d/%Y"))
					with open ("/tmp/job", "w") as f:
						f.write(atcmd)
					os.system(atcmd)
				else: 
					with open(jobspath, "a") as f:
						f.write(nmap_cmd_total+"\n")
			else:
				return HttpResponseNotFound('<h1>Incomplete Data</h1>')
			return HttpResponseRedirect(reverse('new_scan', current_app='scans'))
	else:
		form = ScanForm()
	return render(request, 'scans/new_scan.html', {'form': form})

#download a zip of the scan data
@login_required(login_url=login_page)
def scan_download(request,download_id):
	scan= get_object_or_404(Scan, pk=download_id)
	if scan.finished:
		# Open StringIO to grab in-memory ZIP contents
		s = StringIO.StringIO()
		# The zip compressor
		zf = zipfile.ZipFile(s, "w", zipfile.ZIP_DEFLATED)
		path=os.path.join(module_dir,"nmap_results/processed/%s."%download_id)
		files = [path+"xml", path+"gnmap", path+"nmap"]
		for f in files:
			zf.write(f, arcname=os.path.basename(f))
		zf.close()
		response = HttpResponse(s.getvalue(), content_type='application/x-zip-compressed')
		response['Content-Disposition'] = 'attachment; filename=%s.zip'%download_id
		return response
	else:
		return HttpResponseNotFound('<h1>Scan might not be done yet...</h1>')


##### AJAX VIEWS 
#get the scan list
@login_required(login_url=login_page)
def ajax_scan_list(request):
	scan_list = Scan.objects.all().order_by('-id')
	pg = Paginator(scan_list, 10)
	current_page=request.GET.get('page',1)
	try:
		scans=pg.page(current_page)
	except PageNotAnInteger:
		scans=pg.page(1)
	except EmptyPage:
		scans=pg.page(pg.num_pages)
	return render(request, 'scans/scan_list.html', {"scan_list":scans})

#get the server output
@login_required(login_url=login_page)
def ajax_server_output(request):
	#read current output
	with open(os.path.join(module_dir, "current_output"),'r') as f:
		output = f.read()


	context={'output':output}
	return render(request, 'scans/a_server_output.html', context)

#get the server log
@login_required(login_url=login_page)
def ajax_server_log(request):
	#read the log
	log=""
	linenum=0
	for line in reversed(open(os.path.join(module_dir,"log")).readlines()):
		log+=line
		linenum+=1
		if linenum > 10:
			break
	context={'log':log}
	return render(request, 'scans/a_log.html', context)

#get the server jobs
@login_required(login_url=login_page)
def ajax_server_jobs(request):
	#read the jobs
	jobs=""
	linenum=0
	for line in reversed(open(os.path.join(module_dir,"jobs")).readlines()):
		jobs+=line
		linenum+=1
		if linenum > 10:
			break
	context={'jobs':jobs}
	return render(request, 'scans/a_jobs.html', context)

#get the at jobs
@login_required(login_url=login_page)
def ajax_server_at(request):
	#read the at
	linenum=0
	at = subprocess.Popen(["atq"], stdout=subprocess.PIPE).communicate()[0]
	context={'at':at}
	return render(request, 'scans/a_at.html', context)

