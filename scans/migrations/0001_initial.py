# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Scan',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(default=b'', max_length=200)),
                ('hosts', models.TextField(default=b'')),
                ('version', models.CharField(max_length=100, null=True, blank=True)),
                ('summary', models.TextField(null=True, blank=True)),
                ('finished', models.BooleanField(default=False)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Scan_Profile',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(default=b'', unique=True, max_length=100)),
                ('cmdline', models.TextField(default=b'')),
                ('author', models.ForeignKey(related_name=b'profile_author', to=settings.AUTH_USER_MODEL)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.AddField(
            model_name='scan',
            name='profile',
            field=models.ForeignKey(related_name=b'scanprofile', to='scans.Scan_Profile'),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='scan',
            name='user',
            field=models.ForeignKey(related_name=b'user', blank=True, to=settings.AUTH_USER_MODEL, null=True),
            preserve_default=True,
        ),
    ]
