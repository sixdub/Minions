from django.db import models
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
import re


# Create your models here.

class Scan(models.Model):
	name=models.CharField(max_length=200,default="")
	hosts=models.TextField(default="")
	profile=models.ForeignKey("Scan_Profile", related_name="scanprofile")
	user = models.ForeignKey(User,blank=True, null=True, related_name="user")
	version =models.CharField(max_length=100, blank=True, null=True)
	summary=models.TextField(blank=True, null=True)
	finished=models.BooleanField(default=False)
	def __unicode__(self):
		return self.args

	#only allow ip addresses and properly formatted host names to pass through. allow comma separated and split by line. 
	def isvalid(self, el):
		el = el.rstrip()
		fqdn = re.findall("(?=^.{4,255}$)(^((?!-)[a-zA-Z0-9-]{0,62}[a-zA-Z0-9]\.)+[a-zA-Z]{2,63}$)", el)
		ips = re.findall("(?:[0-9]{1,3}\.){3}[0-9]{1,3}", el)

		if len(ips) + len(fqdn) <= 0:
			raise ValidationError("Proper FQDN or IP not provided")

	def clean(self):
		for line in self.hosts.split("\n"): #if your hosts field can have multiple lines, you can remove this
			elems = line.split(",")#creates an array from comma separated values
			if line:
				for el in elems:
					self.isvalid(el)


class Scan_Profile(models.Model):
	name=models.CharField(max_length=100, default="", unique=True)
	author=models.ForeignKey(User, related_name="profile_author")
	cmdline=models.TextField(default="")
	def __unicode__(self):
		return self.name

	#dont allow any output format. We handle that :)
	def clean(self):
		if "nmap" in self.cmdline:
			 raise ValidationError('Do not place "nmap" in the command line arguments!')
		m = re.findall("-o[A-Z]", self.cmdline)
		if m:
			 raise ValidationError('No "-o" flags... We will decide the output for you!')

