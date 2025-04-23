from netbox.plugins import PluginMenuItem, PluginMenuButton
# from utilities.choices import ButtonColorChoices

subnetauditupdated_buttons=[
    PluginMenuButton(
        link='plugins:netbox_subnet_audit_updated:subnetauditupdated_add',
        title='Add Subnet Audit',
        icon_class='mdi mdi-plus-thick',
        color='green'
    )
]

menu_items = (
    PluginMenuItem(
        link='plugins:netbox_subnet_audit_updated:subnetauditupdated_list',
        link_text='Subnet Audits',
        buttons=subnetauditupdated_buttons
    ),
)
