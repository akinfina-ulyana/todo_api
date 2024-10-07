from sndhdr import tests

from rest_framework import serializers
from django.contrib.auth.models import User

from api.models import Task, Category, Priority


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)  #  поле только для записи

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'password']

        extra_kwargs = {
            'username': {'required': True},
            'email': {'required': True},
            'first_name': {'required': True},
            'last_name': {'required': True},
        }

    def create(self, validated_data):
        user = User(**validated_data)
        user.set_password(validated_data['password'])  # Сохраняем пароль в зашифрованном виде
        user.save()
        return user

class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'completed_at', 'deleted_at', 'deleted', 'created_by']


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = '__all__'


class PrioritySerializer(serializers.ModelSerializer):
    class Meta:
        model = Priority
        fields = '__all__'
