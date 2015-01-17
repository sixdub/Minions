from django import forms
from django.db import models
from scans.models import Scan, Scan_Profile
from datetime import datetime
from django.contrib.admin import widgets  
from django.core.exceptions import ValidationError
import re

class ScanForm(forms.ModelForm):
	time=forms.DateTimeField(initial=datetime.now)
	class Meta:
		model=Scan
		fields = ['name', 'hosts','profile']

class ScanProfileForm(forms.ModelForm):
	class Meta:
		model = Scan_Profile
		fields = ['name', 'cmdline']
