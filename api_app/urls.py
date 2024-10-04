from django.urls import path
# from .views import CreateZoneView, GetZoneDataView
#
# urlpatterns = [
#     path('api/create-zone/', CreateZoneView.as_view(), name='create_zone'),
#     path('api/get-zone-data/', GetZoneDataView.as_view(), name='get_zone_data'),
# ]

from django.urls import path
from .views import UserLogin, Zones, Network

urlpatterns = [
    path('login/', UserLogin.as_view(), name='login'),
    path('zones/', Zones.as_view(), name='zones'),
    path('network/', Network.as_view(), name='network'),
]
