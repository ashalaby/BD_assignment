from django.core import serializers
from django.http import HttpResponse
from django.http import JsonResponse
from django.shortcuts import render
from django.views import View
from django.views.generic import DetailView
from django.views.generic import ListView

from global_app.models import *


def index(request):
    return render(request, 'index.html')


class GetJSON(View):

    def get(self, request, year):
        data = NvdcveDetails.objects.filter(cve_id__icontains='CVE-{}'.format(year))
        json_data = serializers.serialize('json', data)
        res = HttpResponse(json_data, content_type='application/json')
        res['Content-Disposition'] = 'attachment; filename=jsonData.json'
        return res


class SelectYear(ListView):
    paginate_by = 30
    template_name = 'index.html'
    model = NvdcveDetails
    year = 2002

    def get(self, request, *args, **kwargs):
        self.object_list = self.model.objects.filter(cve_id__icontains='CVE-{}'.format(kwargs['year']))
        score_filter = request.GET.get('score_filter')
        apc_filter = request.GET.get('apc_filter')
        download = request.GET.get('download_json')

        self.year = kwargs['year']

        if score_filter:
            self.object_list = self.object_list.filter(score=score_filter)
        if apc_filter:
            self.object_list = self.object_list.filter(num_of_affected_products=apc_filter)

        return super(SelectYear, self).get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(SelectYear, self).get_context_data(**kwargs)
        context['year'] = self.year
        return context

    def get_queryset(self):
        return self.object_list.all()


class GetDetail(View):
    template_name = 'details.html'

    def get(self, request, cv_id):
        modelDetails = NvdcveDetails.objects.get(cve_id=cv_id)
        modelNVDRef = NvdcveReferences.objects.filter(cve_id=cv_id)
        modelNVDprod = NvdcveAffectedProducts.objects.filter(cve_id=cv_id)
        return render(request, self.template_name, {'details': modelDetails,
                                                    'ref': modelNVDRef.all(),
                                                    'prod':modelNVDprod.all()})


class getModified(ListView):
    paginate_by = 30
    template_name = 'modified.html'
    model = NvdcveModifiedDetails

    def get(self, request, *args, **kwargs):
        self.object_list = self.model.objects.filter()
        return super(getModified, self).get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(getModified, self).get_context_data(**kwargs)
        return context

    def get_queryset(self):
        return self.object_list.all()



class getRecent(ListView):
    paginate_by = 30
    template_name = 'recent.html'
    model = NvdcveRecentDetails


    def get(self, request, *args, **kwargs):
        self.object_list = self.model.objects.filter()
        return super(getRecent, self).get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(getRecent, self).get_context_data(**kwargs)
        return context

    def get_queryset(self):
        return self.object_list.all()



