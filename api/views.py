from django.utils import timezone

from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from django.utils.crypto import get_random_string
from rest_framework import generics, status, viewsets, permissions
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.contrib.auth.models import User
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Task, Category, Priority
from .serializers import UserSerializer, TaskSerializer, CategorySerializer, PrioritySerializer


class UserCreate(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Создать нового пользователя",
        request_body=UserSerializer,
        responses={
            201: openapi.Response(
                description="Пользователь успешно создан",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'username': openapi.Schema(type=openapi.TYPE_STRING, description='Имя пользователя'),
                    },
                ),
            ),
            400: openapi.Response(
                description="Неверные данные",
            ),
        },
    )
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()  # Создание пользователя
        return Response({'username': user.username}, status=status.HTTP_201_CREATED)


class CustomAuthToken(ObtainAuthToken):
    @swagger_auto_schema(
        operation_description="Получить токен для аутентификации пользователя",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING, description='Имя пользователя'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='Пароль пользователя'),
            },
        ),
        responses={
            200: openapi.Response(
                description="Токен успешно получен",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'token': openapi.Schema(type=openapi.TYPE_STRING, description='Токен аутентификации'),
                    },
                ),
            ),
            400: openapi.Response(
                description="Неверные учетные данные",
            ),
        },
    )
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({'token': token.key}, status=status.HTTP_200_OK)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Выход пользователя и удаление токена",
        responses={
            200: openapi.Response(
                description="Токен успешно удален",
            ),
            401: openapi.Response(
                description="Пользователь не аутентифицирован",
            ),
        },
    )
    def post(self, request):
        request.user.auth_token.delete()  # Удаляем токен
        return Response(status=status.HTTP_200_OK)


# ---------------------------- User API ----------------------------
# Получить всех пользователей
# GET: Возвращает список всех пользователей (все объекты из User).
# POST: Создаёт нового пользователя, используя данные из запроса.
class UserViewSet(generics.ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    @swagger_auto_schema(
        operation_description="Получить список пользователей или создать нового пользователя",
        responses={
            200: openapi.Response(
                description="Список пользователей",
                schema=openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'id': openapi.Schema(type=openapi.TYPE_INTEGER, description='ID пользователя'),
                            'username': openapi.Schema(type=openapi.TYPE_STRING, description='Имя пользователя'),
                            'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email пользователя'),
                            'first_name': openapi.Schema(type=openapi.TYPE_STRING, description='Имя'),
                            'last_name': openapi.Schema(type=openapi.TYPE_STRING, description='Фамилия'),
                        },
                    ),
                ),
            ),
            201: openapi.Response(
                description="Пользователь успешно создан",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'username': openapi.Schema(type=openapi.TYPE_STRING, description='Имя пользователя'),
                        'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email пользователя'),
                        'first_name': openapi.Schema(type=openapi.TYPE_STRING, description='Имя'),
                        'last_name': openapi.Schema(type=openapi.TYPE_STRING, description='Фамилия')
                    },
                ),
            ),
            400: openapi.Response(
                description="Неверные данные для создания пользователя",
            ),
        },
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


# GET: Возвращает информацию о конкретном пользователе по ID.
# PUT / PATCH: Обновляет информацию о пользователе.
# DELETE: Удаляет пользователя.
class UserDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    @swagger_auto_schema(
        operation_description="Получить пользователя по ID",
        responses={
            200: openapi.Response(
                description="Данные пользователя",
                schema=UserSerializer,
            ),
            404: openapi.Response(
                description="Пользователь не найден",
            ),
        },
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Обновить данные пользователя",
        request_body=UserSerializer,
        responses={
            200: openapi.Response(
                description="Данные пользователя успешно обновлены",
                schema=UserSerializer,
            ),
            400: openapi.Response(
                description="Неверные данные",
            ),
            404: openapi.Response(
                description="Пользователь не найден",
            ),
        },
    )
    def put(self, request, *args, **kwargs):
        return super().put(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Удалить пользователя",
        responses={
            204: openapi.Response(
                description="Пользователь успешно удален",
            ),
            403: openapi.Response(
                description="Нет прав для удаления пользователя",
            ),
            404: openapi.Response(
                description="Пользователь не найден",
            ),
        },
    )
    def destroy(self, request, *args, **kwargs):
        user = self.get_object()
        if request.user.is_staff:  # Проверка, является ли пользователь администратором
            user.delete()  # Жесткое удаление
            return Response(status=status.HTTP_204_NO_CONTENT)
        else:
            user.deleted = True  # Мягкое удаление
            user.save()
            return Response(status=status.HTTP_204_NO_CONTENT)


# Login и lolout для пользователя реализованы стандартными средствами DRF
# Изменение пароля (требует аутентификации, встроенная от DRF)
class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Смена пароля пользователя",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'old_password': openapi.Schema(type=openapi.TYPE_STRING, description='Старый пароль пользователя'),
                'new_password': openapi.Schema(type=openapi.TYPE_STRING, description='Новый пароль пользователя'),
            },
            required=['old_password', 'new_password'],
        ),
        responses={
            200: openapi.Response(
                description="Пароль успешно изменен",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING,
                                                  description='Сообщение об успешной смене пароля'),
                    },
                ),
            ),
            400: openapi.Response(
                description="Старый пароль неверен",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING, description='Сообщение об ошибке'),
                    },
                ),
            ),
        },
    )
    def post(self, request):
        user = request.user
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        if user.check_password(old_password):  # сверка переданного пароля со старым
            user.set_password(new_password)  # хэширует новый пароль и сохраняет его в базе данных
            user.save()
            return Response({"message": "Password changed successfully"}, status=status.HTTP_200_OK)
        return Response({"error": "Old password is incorrect"}, status=status.HTTP_400_BAD_REQUEST)


# Сброс пароля (доступен всем)
class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Сброс пароля пользователя",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email пользователя'),
            },
            required=['email'],
        ),
        responses={
            200: openapi.Response(
                description="Пароль успешно сброшен",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING, description='Сообщение о сбросе пароля'),
                    },
                ),
            ),
            404: openapi.Response(
                description="Пользователь не найден",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING, description='Сообщение об ошибке'),
                    },
                ),
            ),
        },
    )
    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
            new_password = get_random_string(length=12)
            # тут можно отправитьинформацию на почту
            user.set_password(new_password)
            user.save()
            return Response({"message": "Password reset successful. New password: {}".format(new_password)},
                            status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)


class TaskCreateView(generics.CreateAPIView):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Создание новой задачи",
        request_body=TaskSerializer,
        responses={
            201: openapi.Response(
                description="Задача успешно создана",
                schema=TaskSerializer,
            ),
            400: openapi.Response(
                description="Неверные данные для создания задачи",
            ),
        },
    )
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)  # Устанавливаю поле created_by на текущего пользователя


class UserTasksView(generics.ListAPIView):
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Получить список задач, созданных текущим пользователем",
        responses={
            200: openapi.Response(
                description="Список задач текущего пользователя",
                schema=openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=TaskSerializer,
                ),
            ),
            401: openapi.Response(
                description="Необходима аутентификация",
            ),
        },
    )
    def get_queryset(self):
        return Task.objects.filter(created_by=self.request.user)


# ---------------------------- Task API ----------------------------
class TasksByStatusView(generics.ListAPIView):
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        status = self.request.query_params.get('status')  # Получаем статус из параметров запроса
        return Task.objects.filter(created_by=self.request.user, status=status)


class TasksByCategoryView(generics.ListAPIView):
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        category_id = self.request.query_params.get('category')  # Получаем ID категории из параметров запроса
        return Task.objects.filter(created_by=self.request.user, category_id=category_id)


class TasksByPriorityView(generics.ListAPIView):
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        priority_id = self.request.query_params.get('priority')  # Получаем ID приоритета из параметров запроса
        return Task.objects.filter(created_by=self.request.user, priority_id=priority_id)


class UserTaskDetailView(generics.RetrieveAPIView):
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Task.objects.filter(created_by=self.request.user)  # Только задачи текущего пользователя


class TaskUpdateView(generics.UpdateAPIView):
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Task.objects.filter(created_by=self.request.user)  # Обновление только задач текущего пользователя


class TaskDeleteView(generics.DestroyAPIView):
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Task.objects.all()  # Для удаления задачи администратором

    def perform_destroy(self, instance):
        if self.request.user.is_staff:  # Если пользователь администратор
            instance.delete()  # Физическое удаление
        else:
            instance.deleted = True  # Логическое удаление
            instance.deleted_at = timezone.now()  # Устанавливаем время удаления
            instance.save()  # Сохраняем изменения


# ---------------------------- Category API ---------------------------- #

class CategoryViewSet(viewsets.ModelViewSet):
    queryset = Category.objects.filter(deleted=False)
    serializer_class = CategorySerializer
    permission_classes = [permissions.IsAuthenticated]  # Настроить права доступа

    def perform_destroy(self, instance):  # Логика для мягкого удаления
        instance.deleted = True
        instance.deleted_at = timezone.now()  # Установить дату удаления
        instance.save()

    def delete(self, request, pk=None):
        category = self.get_object()
        if request.user.is_staff:  # Проверка для жесткого удаления
            category.delete()  # Жесткое удаление
            return Response(status=status.HTTP_204_NO_CONTENT)
        else:
            self.perform_destroy(category)  # Мягкое удаление
            return Response(status=status.HTTP_204_NO_CONTENT)


class PriorityViewSet(viewsets.ModelViewSet):
    queryset = Priority.objects.filter(deleted=False)
    serializer_class = PrioritySerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_destroy(self, instance):
        # Логика для мягкого удаления
        instance.deleted = True
        instance.deleted_at = timezone.now()
        instance.save()

    def delete(self, request, pk=None):
        priority = self.get_object()
        if request.user.is_admin:  # Проверка для жесткого удаления
            priority.delete()  # Жесткое удаление
            return Response(status=status.HTTP_204_NO_CONTENT)
        else:
            self.perform_destroy(priority)  # Мягкое удаление
            return Response(status=status.HTTP_204_NO_CONTENT)
