from datetime import timezone

from django.contrib.auth import authenticate, login, logout
from django.utils.crypto import get_random_string
from rest_framework import generics, status, viewsets, permissions
from django.contrib.auth.models import User
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Task, Category
from .serializers import UserSerializer, TaskSerializer, CategorySerializer


# ---------------------------- User API ----------------------------
# Получить всех пользователей
# GET: Возвращает список всех пользователей (все объекты из User).
# POST: Создаёт нового пользователя, используя данные из запроса.
class UserViewSet(generics.ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer


# GET: Возвращает информацию о конкретном пользователе по ID.
# PUT / PATCH: Обновляет информацию о пользователе.
# DELETE: Удаляет пользователя.
class UserDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

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
# Изменение пароля (требует аутентификации)
class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        if user.check_password(old_password): # сверка переданного пароля со старым
            user.set_password(new_password) # хэширует новый пароль и сохраняет его в базе данных
            user.save()
            return Response({"message": "Password changed successfully"}, status=status.HTTP_200_OK)
        return Response({"error": "Old password is incorrect"}, status=status.HTTP_400_BAD_REQUEST)

# Сброс пароля (доступен всем)
class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
            new_password = get_random_string(length=12)  # Генерация нового пароля
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

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)  # Устанавливаю поле created_by на текущего пользователя


class UserTasksView(generics.ListAPIView):
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]

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

    def perform_destroy(self, instance): # Логика для мягкого удаления
        instance.deleted = True
        instance.deleted_at = timezone.now()  # Установить дату удаления
        instance.save()

    def delete(self, request, pk=None):
        category = self.get_object()
        if request.user.is_admin:  # Проверка для жесткого удаления
            category.delete()  # Жесткое удаление
            return Response(status=status.HTTP_204_NO_CONTENT)
        else:
            self.perform_destroy(category)  # Мягкое удаление
            return Response(status=status.HTTP_204_NO_CONTENT)









