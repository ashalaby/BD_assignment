from __future__ import unicode_literals

from django.db import models
from datetime import datetime


class NvdcveDetails(models.Model):
    cve_id = models.CharField(max_length=30)
    summary = models.TextField()
    published = models.DateTimeField()
    last_modified = models.DateTimeField()
    score = models.DecimalField(max_digits=65535, decimal_places=65535)
    num_of_affected_products = models.IntegerField()
    access_vector = models.CharField(max_length=20)
    access_complexity = models.CharField(max_length=20)
    authentication = models.CharField(max_length=20)
    confidentiality_impact = models.CharField(max_length=20)
    integrity_impact = models.CharField(max_length=20)
    source = models.TextField()
    generated_on = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'nvdcve_details'


class NvdcveModifiedAffectedProducts(models.Model):
    cve_id = models.CharField(max_length=30)
    product = models.TextField()

    class Meta:
        managed = False
        db_table = 'nvdcve_modified_affected_products'


class NvdcveModifiedDetails(models.Model):
    cve_id = models.CharField(max_length=30)
    summary = models.TextField()
    published = models.DateTimeField()
    last_modified = models.DateTimeField()
    score = models.DecimalField(max_digits=65535, decimal_places=65535)
    num_of_affected_products = models.IntegerField()
    access_vector = models.CharField(max_length=20)
    access_complexity = models.CharField(max_length=20)
    authentication = models.CharField(max_length=20)
    confidentiality_impact = models.CharField(max_length=20)
    integrity_impact = models.CharField(max_length=20)
    source = models.TextField()
    generated_on = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'nvdcve_modified_details'


class NvdcveModifiedReferences(models.Model):
    cve_id = models.CharField(max_length=30)
    url = models.TextField()

    class Meta:
        managed = False
        db_table = 'nvdcve_modified_references'


class NvdcveReferences(models.Model):
    cve_id = models.CharField(max_length=30)
    url = models.TextField()
    year = models.CharField(max_length=4)

    class Meta:
        managed = False
        db_table = 'nvdcve_references'
        
class NvdcveRecentAffectedProducts(models.Model):
    cve_id = models.TextField()
    product = models.TextField()

    class Meta:
        managed = False
        db_table = 'nvdcve_recent_affected_products'


class NvdcveRecentDetails(models.Model):
    cve_id = models.TextField()
    summary = models.DateTimeField()
    published = models.DateTimeField()
    last_modified = models.TextField()
    score = models.DecimalField(max_digits=65535, decimal_places=65535, )
    num_of_affected_products = models.IntegerField()
    access_vector = models.TextField()
    access_complexity = models.TextField()
    authentication = models.TextField()
    confidentiality_impact = models.TextField()
    integrity_impact = models.TextField()
    source = models.TextField()
    generated_on = models.TextField()

    class Meta:
        managed = False
        db_table = 'nvdcve_recent_details'


class NvdcveRecentReferences(models.Model):
    cve_id = models.TextField()
    url = models.TextField()

    class Meta:
        managed = False
        db_table = 'nvdcve_recent_references'


class NvdcveAffectedProducts(models.Model):
    cve_id = models.TextField()
    product = models.TextField()

    class Meta:
        managed = False
        db_table = 'nvdcve_affected_products'