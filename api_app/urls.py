from django.urls import path
# from .views import CreateZoneView, GetZoneDataView
#
# urlpatterns = [
#     path('api/create-zone/', CreateZoneView.as_view(), name='create_zone'),
#     path('api/get-zone-data/', GetZoneDataView.as_view(), name='get_zone_data'),
# ]

from django.urls import path
from .views import UserLogin, Zones, Network
from .views import Contracts, SubjectHandler
from .views import Filters, EntryHandler, ContractMapping
from .views import SecurityGroup, SecurityGroupRule
from .views import ColoPolicyGroup, UpdateVpcPolicyGroup, ColoAccessPort, ColoStaticEpgView
from .views import L3OutView, ExtSubnetView
from .views import NodeProfileView, ConfiguredNodeView, StaticRouteView
from .views import InterfaceProfileView, RoutedInterfaceView
from .views import SviInterfaceProfileAPIView, SviRoutedInterfaceAPIView

urlpatterns = [
    path('login/', UserLogin.as_view(), name='login'),
    path('zones/', Zones.as_view(), name='zones'),
    path('network/', Network.as_view(), name='network'),
    path('contracts/', Contracts.as_view(), name='contracts'),
    path('subject/<str:contract_name>/', SubjectHandler.as_view(), name='subject_handler'),
    path('filters/', Filters.as_view(), name='filters'),
    path('entry/<str:filter_name>/', EntryHandler.as_view(), name='entry_handler'),
    path('contract_mapping/', ContractMapping.as_view(), name='contract_mapping'),
    path('security_group/', SecurityGroup.as_view(), name='security_group'),
    path('security_group_rule/<str:security_group_id>/', SecurityGroupRule.as_view(), name='security_group_rule'),
    path('colo_policy_group/', ColoPolicyGroup.as_view(), name='colo_policy_group'),
    path('update_vpc_policy_group/', UpdateVpcPolicyGroup.as_view(), name='update_vpc_policy_group'),
    path('colo_access_port/', ColoAccessPort.as_view(), name='colo-access-port'),
    path('colo_access_port/fetch-node-details/<str:node_id>/', ColoAccessPort.as_view(), name='fetch-node-details'),
    path('colo_access_port/fetch-interface-details/<str:profile_name>/', ColoAccessPort.as_view(),
         name='fetch-interface-details'),
    path('deploy_static_epg/', ColoStaticEpgView.as_view(), name="deploy_static_epg"),
    path('deploy_static_epg/<str:action>/', ColoStaticEpgView.as_view(), name="fetch-epgs"),
    path('deploy_static_epg/<str:action>/<str:ap_name>/', ColoStaticEpgView.as_view(), name="fetch-epg-details"),
    path('l3out/', L3OutView.as_view(), name="l3out"),
    path('ext_subnet/', ExtSubnetView.as_view(), name='ext_subnet'),
    path('ext_subnet/<str:l3out_name>/', ExtSubnetView.as_view(), name='ext_subnet'),
    path('node_profile/', NodeProfileView.as_view(), name='node_profile'),
    path('node_profile/<str:l3out_name>/', NodeProfileView.as_view(), name='node_profile'),
    path('configured_node/', ConfiguredNodeView.as_view(), name='configured_node'),
    path('static_route/', StaticRouteView.as_view(), name='static_route'),
    path('interface_profile/', InterfaceProfileView.as_view(), name='interface_profile'),
    path('interface_profile/<str:l3out_name>/', InterfaceProfileView.as_view(), name='interface_profile'),
    path('routed_interface/', RoutedInterfaceView.as_view(), name='routed_interface'),
    path('svi_interface_profile/', SviInterfaceProfileAPIView.as_view(), name='svi_interface_profile'),
    path('svi_interface_profile/<str:l3out_name>/', SviInterfaceProfileAPIView.as_view(), name='svi_interface_profile'),
    path('svi_routed_interface/', SviRoutedInterfaceAPIView.as_view(), name='svi_routed_interface'),
]
