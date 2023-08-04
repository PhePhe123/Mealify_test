#helps manage the transfer of incoming data, creating tokens etc
from rest_framework.validators import UniqueValidator
from rest_framework_simplejwt.tokens import api_settings
from rest_framework import serializers
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView,TokenVerifyView 


class UserSerializer(serializers.ModelSerializer):

    token = serializers.SerializerMethodField()

    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
        )

    username = serializers.CharField(
        required=True,
        max_length=32,
        validators=[UniqueValidator(queryset=User.objects.all())]
        )

    first_name = serializers.CharField(
        required=True,
        max_length=32,
        )

    last_name = serializers.CharField(
        required=True,
        max_length=32,
        )

    password = serializers.CharField(
        required=True,
        min_length=8,
        write_only=True
        )

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance

    def get_token(self, obj):
        refresh = RefreshToken.for_user(obj)

        token = "Bearer" + " " + str(refresh.access_token)
        # {
        #     'refresh': str(refresh),
        #     'access': str(refresh.access_token),
        # }


        return token


    class Meta:
        model=User
        fields = (
            'token',
            'username',
            'password',
            'first_name',
            'last_name',
            'email',
            'id'
            )