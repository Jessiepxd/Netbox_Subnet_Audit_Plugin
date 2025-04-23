from netbox.forms import NetBoxModelForm
from utilities.forms.fields import CommentField
from .models2 import SubnetAuditUpdated

from django import forms
from netbox.forms import NetBoxModelForm, NetBoxModelFilterSetForm
from .models2 import SubnetAuditUpdated, SubnetAuditStatusChoicesUpdated

import logging
logger = logging.getLogger('netbox_subnet_audit_updated')

class SubnetAuditUpdatedForm(NetBoxModelForm):
    comments = CommentField()

    class Meta:
        model = SubnetAuditUpdated
        fields = ['subnet']
        # fields = ['subnet', 'created_by']

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        logger.info(f"Form received user: {user}. [forms.py]")
        logger.info(f"Form received user.username: {user.username}. [forms.py]")
        super().__init__(*args, **kwargs)

        # if user and not self.instance.pk:  # For new instances
        # if user:
        #     self.fields['created_by'].initial = user.username
        #     self.fields['created_by'].widget = forms.TextInput(attrs={'readonly': 'readonly'})
        #     logger.info(f"Setting initial value for created_by: {self.fields['created_by'].initial}. [forms.py]")
        # else:
        #     self.fields['created_by'].widget = forms.TextInput(attrs={'readonly': 'readonly'})
        #     self.fields['created_by'].initial = self.instance.created_by.username if self.instance.created_by else ""

class SubnetAuditUpdatedFilterForm(NetBoxModelFilterSetForm):
    model = SubnetAuditUpdated

    status = forms.MultipleChoiceField(
        choices=SubnetAuditStatusChoicesUpdated.CHOICES,
        required=False
    )
    subnet = forms.GenericIPAddressField(
        required=False,
        label="Subnet (IP Filter)"
    )
