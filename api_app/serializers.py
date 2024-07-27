from rest_framework import serializers

class ZoneSerializer(serializers.Serializer):
    zone_name = serializers.CharField(max_length=100)

class GetZoneSerializer(serializers.Serializer):
    vrf_name = serializers.CharField(max_length=100)
