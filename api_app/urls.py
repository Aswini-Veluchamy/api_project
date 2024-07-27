from django.urls import path
from .views import CreateZoneView, TestView, GetZoneDataView

urlpatterns = [
    path('create-zone/', CreateZoneView.as_view(), name='create_zone'),
    path('test/', TestView.as_view(), name='test_view'),
    path('get-zones/', GetZoneDataView.as_view(), name='get_zones'),
]
