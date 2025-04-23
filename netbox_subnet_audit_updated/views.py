from netbox.views import generic
from . import models2, tables, forms, filtersets
from .models2 import AuditRecordUpdated, SubnetAuditUpdated
from django.contrib.auth.models import User
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render
from django.contrib import messages  # For success and error messages
from django.shortcuts import redirect  # For redirecting to another URL

from django.http import JsonResponse
from rq.job import Job
from django_rq import get_queue
def check_job_status(request, pk):
    try:
        audit = SubnetAuditUpdated.objects.get(pk=pk)
        if audit.job_id:
            queue = get_queue('default')
            job = Job.fetch(audit.job_id, connection=queue.connection)
            return JsonResponse({'status': job.get_status()})
        else:
            return JsonResponse({'error': 'No job associated with this audit.'}, status=404)
    except SubnetAuditUpdated.DoesNotExist:
        return JsonResponse({'error': 'Audit not found.'}, status=404)


import logging
logger = logging.getLogger('netbox_subnet_audit_updated')


class SubnetAuditUpdatedView(generic.ObjectView):
    queryset = models2.SubnetAuditUpdated.objects.all()
    template_name = 'netbox_subnet_audit_updated/subnetauditupdated.html'

    def get_extra_context(self, request, instance):
        # audit_records = AuditRecordUpdated.objects.filter(subnet_audit=instance)
        audit_records = instance.audit_records.all()
        logger.info(f"Running get_extra_contex in SubnetAuditUpdatedView class. [views.py]")
        return {
            'audit_records': audit_records,
        }


class SubnetAuditUpdatedListView(generic.ObjectListView):
    queryset = models2.SubnetAuditUpdated.objects.all()
    table = tables.SubnetAuditUpdatedTable

class SubnetAuditUpdatedEditView(LoginRequiredMixin, generic.ObjectEditView):
    queryset = models2.SubnetAuditUpdated.objects.all()
    form = forms.SubnetAuditUpdatedForm
    logger.info(f"SubnetAuditUpdatedEditView is running. [views.py]")

    # def dispatch(self, request, *args, **kwargs):
    #     logger.info(f"Dispatch called with user {request.user} in SubnetAuditUpdatedEditView. [views.py]")
    #     # raise Exception("SubnetAuditUpdatedEditView dispatch called. [views.py]")
    #     return super().dispatch(request, *args, **kwargs)

    # def get_form_kwargs(self, request, *args, **kwargs):
    def get_form_kwargs(self):
        """
        Pass the current user to the form.
        """
        logger.info("get_form_kwargs is running. [views.py]")
        kwargs = super().get_form_kwargs()
        logger.info(f"Passing user {self.request.user} to the form in get_form_kwargs. [views.py]")
        kwargs['user'] = self.request.user
        return kwargs

    def form_valid(self, form):
        """
        Logic for saving a valid form.
        """
        logger.info(f"Form is valid. Saving the object for user {self.request.user}. [views.py]")
        obj = form.save(commit=False)  # Don't commit immediately
        obj.save(user=self.request.user)  # Pass the user to the model's save method
        messages.success(self.request, f"Subnet audit {obj} has been successfully created/updated.")
        return redirect(self.get_return_url(self.request, obj))

    def form_invalid(self, form):
        """
        Logic for handling an invalid form.
        """
        logger.info("Form is invalid. Re-rendering the form with errors. [views.py]")
        return render(self.request, self.template_name, {
            'model': self.queryset.model,
            'form': form,
            'return_url': self.get_return_url(self.request),
        })

    def get(self, request, *args, **kwargs):
        """
        Handle GET requests and pass the user to the form.
        """
        logger.info("Handling GET request in SubnetAuditUpdatedEditView. [views.py]")
        obj = self.get_object(**kwargs)  # Retrieve the object being edited or a new instance
        form = self.form(instance=obj, user=request.user)  # Pass the user to the form
        return render(request, self.template_name, {
            'model': self.queryset.model,
            'object': obj,
            'form': form,
            'return_url': self.get_return_url(request, obj),
        })

    def post(self, request, *args, **kwargs):
        """
        Handle POST requests and pass the user to the form.
        """
        logger.info("Handling POST request in SubnetAuditUpdatedEditView. [views.py]")
        obj = self.get_object(**kwargs)  # Retrieve the object being edited or a new instance
        form = self.form(data=request.POST, files=request.FILES, instance=obj, user=request.user)  # Pass the user to the form
        if form.is_valid():
            # logger.info("Form is valid. Saving the object.")
            # obj = form.save()
            # messages.success(request, f"Subnet audit {obj} has been successfully created/updated.")
            # return redirect(self.get_return_url(request, obj))
            return self.form_valid(form)
        else:
            # logger.info("Form is invalid. Re-rendering the form with errors.")
            # return render(request, self.template_name, {
            #     'model': self.queryset.model,
            #     'object': obj,
            #     'form': form,
            #     'return_url': self.get_return_url(request, obj),
            # })
            return self.form_invalid(form)


class SubnetAuditUpdatedDeleteView(generic.ObjectDeleteView):
    queryset = models2.SubnetAuditUpdated.objects.all()

class SubnetAuditUpdatedListView(generic.ObjectListView):
    queryset = models2.SubnetAuditUpdated.objects.all()
    table = tables.SubnetAuditUpdatedTable
    filterset = filtersets.SubnetAuditUpdatedFilterSet
    filterset_form = forms.SubnetAuditUpdatedFilterForm