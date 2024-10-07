from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token

from api.models import Task, Category, Priority

User = get_user_model()


class UserCreateTests(APITestCase):  # APITestCase для тестирования API

    def setUp(self):  # определяем URL для регистрации пользователя
        self.url = reverse('user-register')

    def test_create_user_success(self):
        data = {
            'username': 'testuser',
            'email': 'testuser@example.com',
            'first_name': 'First',
            'last_name': 'Last',
            'password': 'testpassword123'
        }
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(User.objects.get().username, 'testuser')

    def test_create_user_missing_fields(self):
        data = {
            'username': 'testuser',
            'password': 'testpassword123'
        }
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)
        self.assertIn('first_name', response.data)
        self.assertIn('last_name', response.data)

    def test_create_user_duplicate_username(self):
        User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='testpassword123'
        )
        data = {
            'username': 'testuser',
            'email': 'newuser@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'password': 'newpassword123'
        }
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('username', response.data)

    def test_create_user_invalid_email(self):
        data = {
            'username': 'testuser',
            'email': 'invalidemail',  # Неверный формат email
            'first_name': 'First',
            'last_name': 'Last',
            'password': 'testpassword123'
        }
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)


class CustomAuthTokenTests(APITestCase):

    def setUp(self):
        self.url = reverse('api-token-auth')
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            first_name='First',
            last_name='Last',
            password='testpassword123'
        )

    def test_authenticate_user_success(self):
        data = {
            'username': 'testuser',
            'password': 'testpassword123'
        }
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)
        self.assertEqual(Token.objects.count(), 1)
        self.assertEqual(Token.objects.get(user=self.user).key, response.data['token'])

    def test_authenticate_user_invalid_credentials(self):
        data = {
            'username': 'testuser',
            'password': 'wrongpassword'
        }
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)

    def test_authenticate_user_nonexistent_user(self):
        data = {
            'username': 'nonexistentuser',
            'password': 'somepassword'
        }
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)


class LogoutViewTests(APITestCase):

    def setUp(self):
        self.url = reverse('logout')
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            first_name='First',
            last_name='Last',
            password='testpassword123'
        )
        self.token = Token.objects.create(user=self.user)

    def test_logout_success(self):
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token.key)
        response = self.client.post(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(Token.objects.count(), 0)  # Убедитесь, что токен удален

    def test_logout_unauthenticated(self):
        response = self.client.post(self.url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)  # Проверка, что доступ запрещен


class UserViewSetTests(APITestCase):

    def setUp(self):
        self.url = reverse('user-list')  # Убедитесь, что у вас правильный URL
        self.user1 = User.objects.create_user(
            username='user1',
            email='user1@example.com',
            first_name='First',
            last_name='Last',
            password='password123'
        )
        self.user2 = User.objects.create_user(
            username='user2',
            email='user2@example.com',
            first_name='First',
            last_name='Last',
            password='password123'
        )

    def test_list_users_authenticated(self):
        # принудительно аутентифицировать пользователя перед выполнением запросов к защищенному представлению
        self.client.force_authenticate(user=self.user1)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)  # Проверяем, что два пользователя в списке
        self.assertEqual(response.data[0]['username'], self.user1.username)
        self.assertEqual(response.data[1]['username'], self.user2.username)

    def test_create_user_authenticated(self):
        self.client.force_authenticate(user=self.user1)
        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'first_name': 'First',
            'last_name': 'Last',
            'password': 'newpassword123'
        }
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(User.objects.count(), 3)
        self.assertEqual(User.objects.get(username='newuser').email, 'newuser@example.com')

    def test_create_user_unauthenticated(self):
        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'first_name': 'First',
            'last_name': 'Last',
            'password': 'newpassword123'
        }
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class UserDetailTests(APITestCase):

    def setUp(self):
        self.user1 = User.objects.create_user(
            username='user1',
            email='user1@example.com',
            password='password123',
            first_name='First1',
            last_name='Last1'
        )
        self.user2 = User.objects.create_user(
            username='user2',
            email='user2@example.com',
            password='password123',
            first_name='First2',
            last_name='Last2'
        )
        self.admin_user = User.objects.create_superuser(
            username='admin',
            email='admin@example.com',
            password='adminpassword',
            first_name='AdminFirst',
            last_name='AdminLast'
        )
        self.url = reverse('user-detail', kwargs={'pk': self.user1.pk})  # Убедитесь, что у вас правильный URL

    def test_retrieve_user_authenticated(self):
        self.client.force_authenticate(user=self.user1)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], self.user1.username)
        self.assertEqual(response.data['first_name'], self.user1.first_name)
        self.assertEqual(response.data['last_name'], self.user1.last_name)

    def test_update_user_authenticated(self):
        self.client.force_authenticate(user=self.user1)

        data = {
            'email': 'updated_email@example.com',
            'first_name': 'UpdatedFirst',
            'last_name': 'UpdatedLast'
        }
        response = self.client.patch(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user1.refresh_from_db()
        self.assertEqual(self.user1.email, 'updated_email@example.com')

    def test_destroy_user_authenticated(self):
        self.client.force_authenticate(user=self.user1)

        response = self.client.delete(self.url)

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.user1.refresh_from_db()
        self.assertTrue(self.user1.delete)

    def test_destroy_user_admin(self):
        self.client.force_authenticate(user=self.admin_user)

        response = self.client.delete(self.url)

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        with self.assertRaises(User.DoesNotExist):
            self.user1.refresh_from_db()

    def test_retrieve_user_unauthenticated(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_update_user_unauthenticated(self):
        data = {'email': 'unauthenticated@example.com'}
        response = self.client.patch(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_destroy_user_unauthenticated(self):
        response = self.client.delete(self.url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class ChangePasswordViewTests(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='oldpassword123',
            first_name='Test',
            last_name='User'
        )
        self.url = reverse('change-password')

    def test_change_password_success(self):
        self.client.force_authenticate(user=self.user)

        data = {
            'old_password': 'oldpassword123',
            'new_password': 'newpassword123'
        }
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], "Password changed successfully")


        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('newpassword123'))

    def test_change_password_incorrect_old_password(self):
        self.client.force_authenticate(user=self.user)

        data = {
            'old_password': 'wrongpassword',
            'new_password': 'newpassword123'
        }
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], "Old password is incorrect")

    def test_change_password_unauthenticated(self):
        data = {
            'old_password': 'oldpassword123',
            'new_password': 'newpassword123'
        }
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['detail'], "Authentication credentials were not provided.")


class TaskCreateViewTests(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='password123',
            first_name='Test',
            last_name='User'
        )
        self.category = Category.objects.create(name='Test Category')
        self.priority = Priority.objects.create(name='High')
        self.url = reverse('create-task')

    def test_create_task_success(self):
        self.client.force_authenticate(user=self.user)

        data = {
            'title': 'Test Task',
            'description': 'This is a test task.',
            'status': 'pending',
            'completed': False,
            'category': self.category.id,
            'priority': self.priority.id,
        }
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Task.objects.count(), 1)  # Проверяем, что задача создана

        task = Task.objects.get()
        self.assertEqual(task.title, 'Test Task')  # Проверяем заголовок задачи
        self.assertEqual(task.description, 'This is a test task.')  # Проверяем описание задачи
        self.assertEqual(task.status, 'pending')  # Проверяем статус задачи
        self.assertEqual(task.created_by, self.user)  # Проверяем, что задача создана правильным пользователем
        self.assertEqual(task.category, self.category)  # Проверяем, что категория правильно установлена
        self.assertEqual(task.priority, self.priority)  # Проверяем, что приоритет правильно установлен
        self.assertFalse(task.completed)  # Проверяем, что задача не завершена по умолчанию

    def test_create_task_unauthenticated(self):
        data = {
            'title': 'Test Task',
            'description': 'This is a test task.',
            'status': 'pending',
            'completed': False,
            'category': self.category.id,
            'priority': self.priority.id,
        }
        response = self.client.post(self.url, data)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)  # Проверяем, что доступ запрещен


class UserTasksViewTests(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='password123',
            first_name='Test',
            last_name='User'
        )
        self.other_user = User.objects.create_user(
            username='otheruser',
            email='other@example.com',
            password='password456',
            first_name='Test',
            last_name='User'
        )
        self.category = Category.objects.create(name='Test Category')  # Создайте тестовую категорию
        self.priority = Priority.objects.create(name='High')  # Создайте тестовый приоритет

        # Создание задач для текущего пользователя и другого пользователя
        self.task1 = Task.objects.create(
            title='User Task 1',
            description='This is a test task for user.',
            status='pending',
            created_by=self.user,
            category=self.category,
            priority=self.priority
        )
        self.task2 = Task.objects.create(
            title='User Task 2',
            description='Another test task for user.',
            status='pending',
            created_by=self.user,
            category=self.category,
            priority=self.priority
        )
        self.task3 = Task.objects.create(
            title='Other User Task',
            description='This task is for another user.',
            status='pending',
            created_by=self.other_user,
            category=self.category,
            priority=self.priority
        )
        self.url = reverse('user-tasks')  # Убедитесь, что у вас правильный URL

    def test_get_user_tasks_success(self):
        self.client.force_authenticate(user=self.user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)  # Проверяем, что возвращаются только задачи текущего пользователя
        self.assertEqual(response.data[0]['title'], 'User Task 1')  # Проверяем, что первая задача правильная
        self.assertEqual(response.data[1]['title'], 'User Task 2')  # Проверяем, что вторая задача правильная

    def test_get_user_tasks_unauthenticated(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)  # Проверяем, что доступ запрещен


class TasksByStatusViewTests(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='password123',
            first_name='Test',
            last_name='User'
        )
        self.category = Category.objects.create(name='Test Category')  # Создайте тестовую категорию
        self.priority = Priority.objects.create(name='High')  # Создайте тестовый приоритет

        self.task1 = Task.objects.create(
            title='Task 1',
            description='This is a pending task.',
            status='pending',
            created_by=self.user,
            category=self.category,
            priority=self.priority
        )
        self.task2 = Task.objects.create(
            title='Task 2',
            description='This is a completed task.',
            status='completed',
            created_by=self.user,
            category=self.category,
            priority=self.priority
        )
        self.url = reverse('tasks-by-status')

    def test_get_tasks_by_status_success(self):
        self.client.force_authenticate(user=self.user)

        response = self.client.get(self.url, {'status': 'pending'})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)  # Должна вернуться одна задача
        self.assertEqual(response.data[0]['title'], 'Task 1')  # Проверяем, что задача правильная

    def test_get_tasks_by_status_no_tasks(self):
        self.client.force_authenticate(user=self.user)

        response = self.client.get(self.url, {'status': 'nonexistent'})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 0)  # Должно быть 0 задач

    def test_get_tasks_by_status_unauthenticated(self):
        response = self.client.get(self.url, {'status': 'pending'})

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)  # Проверяем, что доступ запрещен


class TasksByCategoryViewTests(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='password123',
            first_name='Test',
            last_name='User'
        )
        self.category1 = Category.objects.create(name='Category 1')  # Создайте тестовую категорию
        self.category2 = Category.objects.create(name='Category 2')  # Создайте другую категорию

        self.task1 = Task.objects.create(
            title='Task 1',
            description='This is a task in Category 1.',
            status='pending',
            created_by=self.user,
            category=self.category1,
            priority=None
        )
        self.task2 = Task.objects.create(
            title='Task 2',
            description='This is a task in Category 2.',
            status='completed',
            created_by=self.user,
            category=self.category2,
            priority=None  # Укажите приоритет, если он требуется
        )
        self.url = reverse('tasks-by-category')  # Убедитесь, что у вас правильный URL

    def test_get_tasks_by_category_success(self):
        self.client.force_authenticate(user=self.user)

        response = self.client.get(self.url, {'category': self.category1.id})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)  # Должна вернуться одна задача
        self.assertEqual(response.data[0]['title'], 'Task 1')  # Проверяем, что задача правильная

    def test_get_tasks_by_category_no_tasks(self):
        self.client.force_authenticate(user=self.user)

        # Пытаемся получить задачи по категории, у которой нет задач
        response = self.client.get(self.url, {'category': self.category2.id})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)  # Должна вернуться одна задача
        self.assertEqual(response.data[0]['title'], 'Task 2')  # Проверяем, что задача правильная

    def test_get_tasks_by_category_unauthenticated(self):
        response = self.client.get(self.url, {'category': self.category1.id})

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)  # Проверяем, что доступ запрещен


class UserTaskDetailViewTests(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='password123',
            first_name='Test',
            last_name='User'
        )
        self.other_user = User.objects.create_user(
            username='otheruser',
            email='other@example.com',
            password='password43',
            first_name='Test',
            last_name='User'
        )

        self.category = Category.objects.create(name='Test Category')
        self.priority = Priority.objects.create(name='High')

        # Создание задач для текущего пользователя и другого пользователя
        self.task = Task.objects.create(
            title='User Task',
            description='This is a task for the test user.',
            status='pending',
            created_by=self.user,
            category=self.category,
            priority=self.priority
        )

        self.other_task = Task.objects.create(
            title='Other User Task',
            description='This task is for another user.',
            status='completed',
            created_by=self.other_user,
            category=self.category,
            priority=self.priority
        )

        self.url = reverse('user-task-detail', args=[self.task.id])

    def test_get_user_task_success(self):
        self.client.force_authenticate(user=self.user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['title'], 'User Task')  # Проверяем, что задача правильная

    def test_get_other_user_task(self):
        self.client.force_authenticate(user=self.user)

        # URL для доступа к задаче другого пользователя
        other_task_url = reverse('user-task-detail', args=[self.other_task.id])
        response = self.client.get(other_task_url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)  # Проверяем, что задача не найдена

    def test_get_user_task_unauthenticated(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)  # Проверяем, что доступ запрещен

    def test_get_nonexistent_task(self):
        self.client.force_authenticate(user=self.user)

        # URL для доступа к несуществующей задаче
        nonexistent_task_url = reverse('user-task-detail', args=[9999])  # ID, который не существует
        response = self.client.get(nonexistent_task_url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)  # Проверяем, что задача не найдена


class TaskUpdateViewTests(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='password123',
            first_name='Test',
            last_name='User'
        )
        self.other_user = User.objects.create_user(
            username='otheruser',
            email='other@example.com',
            password='password456'
        )

        self.category = Category.objects.create(name='Test Category')  # Создайте тестовую категорию
        self.priority = Priority.objects.create(name='High')  # Создайте тестовый приоритет

        # Создание задачи для текущего пользователя
        self.task = Task.objects.create(
            title='User Task',
            description='This is a task for the test user.',
            status='pending',
            created_by=self.user,
            category=self.category,
            priority=self.priority
        )

        self.url = reverse('task-update', args=[self.task.id])  # URL для обновления задачи

    def test_update_user_task_success(self):
        self.client.force_authenticate(user=self.user)

        # Новые данные для обновления
        updated_data = {
            'title': 'Updated User Task',
            'description': 'This task has been updated.',
            'status': 'completed',
            'category': self.category.id,
            'priority': self.priority.id
        }

        response = self.client.put(self.url, updated_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.task.refresh_from_db()  # Обновляем объект из базы данных
        self.assertEqual(self.task.title, 'Updated User Task')  # Проверяем, что заголовок обновился
        self.assertEqual(self.task.status, 'completed')  # Проверяем, что статус обновился

    def test_update_other_user_task(self):
        self.client.force_authenticate(user=self.user)


        other_task = Task.objects.create(
            title='Other User Task',
            description='This task belongs to another user.',
            status='pending',
            created_by=self.other_user,
            category=self.category,
            priority=self.priority
        )


        other_task_url = reverse('task-update', args=[other_task.id])
        updated_data = {
            'title': 'Attempted Update',
            'description': 'This should not be updated.',
            'status': 'completed',
            'category': self.category.id,
            'priority': self.priority.id
        }

        response = self.client.put(other_task_url, updated_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)  # Проверяем, что задача не найдена

    def test_update_user_task_unauthenticated(self):
        updated_data = {
            'title': 'Updated User Task',
            'description': 'This task has been updated.',
            'status': 'completed',
            'category': self.category.id,
            'priority': self.priority.id
        }

        response = self.client.put(self.url, updated_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)  # Проверяем, что доступ запрещен

    def test_update_nonexistent_task(self):
        self.client.force_authenticate(user=self.user)

        # URL для обновления несуществующей задачи
        nonexistent_task_url = reverse('task-update', args=[9999])  # ID, который не существует
        updated_data = {
            'title': 'Attempted Update',
            'description': 'This should not be updated.',
            'status': 'completed',
            'category': self.category.id,
            'priority': self.priority.id
        }

        response = self.client.put(nonexistent_task_url, updated_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)  # Проверяем, что задача не найдена


class TaskDeleteViewTests(APITestCase):

    def setUp(self):
        self.admin_user = User.objects.create_user(
            username='adminuser',
            email='admin@example.com',
            password='adminpassword',
            first_name='Admin',
            last_name='User',
            is_staff=True  # Устанавливаем пользователя как администратора
        )
        self.normal_user = User.objects.create_user(
            username='normaluser',
            email='user@example.com',
            password='userpassword'
        )

        self.category = Category.objects.create(name='Test Category')  # Создайте тестовую категорию
        self.priority = Priority.objects.create(name='High')  # Создайте тестовый приоритет

        # Создание задачи для тестирования
        self.task = Task.objects.create(
            title='Task to Delete',
            description='This task will be deleted.',
            status='pending',
            created_by=self.normal_user,
            category=self.category,
            priority=self.priority
        )

        self.url = reverse('task-delete', args=[self.task.id])  # URL для удаления задачи

    def test_delete_task_as_admin(self):
        self.client.force_authenticate(user=self.admin_user)

        response = self.client.delete(self.url)

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)  # Проверяем, что задача удалена
        self.assertFalse(Task.objects.filter(id=self.task.id).exists())  # Проверяем, что задача не существует

    def test_delete_task_as_normal_user(self):
        self.client.force_authenticate(user=self.normal_user)

        response = self.client.delete(self.url)

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)  # Проверяем, что задача логически удалена
        self.task.refresh_from_db()  # Обновляем объект из базы данных
        self.assertTrue(self.task.deleted)  # Проверяем, что задача помечена как удаленная
        self.assertIsNotNone(self.task.deleted_at)  # Проверяем, что время удаления установлено

    def test_delete_nonexistent_task(self):
        self.client.force_authenticate(user=self.admin_user)

        nonexistent_task_url = reverse('task-delete', args=[9999])  # ID, который не существует
        response = self.client.delete(nonexistent_task_url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)  # Проверяем, что задача не найдена

    def test_delete_task_unauthenticated(self):
        response = self.client.delete(self.url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

class CategoryViewSetTests(APITestCase):

    def setUp(self):
        self.admin_user = User.objects.create_user(
            username='adminuser',
            email='admin@example.com',
            password='adminpassword',
            is_staff=True,  # Устанавливаем пользователя как администратора
            is_superuser=True  # Устанавливаем пользователя как суперпользователя
        )
        self.normal_user = User.objects.create_user(
            username='normaluser',
            email='user@example.com',
            password='userpassword'
        )

        self.url_create = reverse('category-create')  # URL для создания категории

    def test_create_category_success(self):
        self.client.force_authenticate(user=self.normal_user)

        data = {
            'name': 'New Category'
        }

        response = self.client.post(self.url_create, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)  # Проверяем, что категория создана
        self.assertTrue(Category.objects.filter(name='New Category').exists())  # Проверяем, что категория существует

    def test_delete_category_soft(self):
        self.client.force_authenticate(user=self.normal_user)

        # Создаем категорию для удаления
        category = Category.objects.create(name='Category to Delete')
        url_delete = reverse('category-detail', args=[category.id])  # URL для удаления категории

        response = self.client.delete(url_delete)

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)  # Проверяем, что категория мягко удалена
        category.refresh_from_db()  # Обновляем объект из базы данных
        self.assertTrue(category.deleted)  # Проверяем, что категория помечена как удаленная
        self.assertIsNotNone(category.deleted_at)  # Проверяем, что время удаления установлено

    def test_delete_category_hard(self):
        self.client.force_authenticate(user=self.admin_user)

        # Создаем категорию для жесткого удаления
        category = Category.objects.create(name='Category to Hard Delete')
        url_delete = reverse('category-detail', args=[category.id])  # URL для удаления категории

        response = self.client.delete(url_delete)

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)  # Проверяем, что категория жестко удалена
        self.assertFalse(Category.objects.filter(id=category.id).exists())  # Проверяем, что категория не существует

    def test_delete_nonexistent_category(self):
        self.client.force_authenticate(user=self.admin_user)

        nonexistent_category_url = reverse('category-detail', args=[9999])  # ID, который не существует
        response = self.client.delete(nonexistent_category_url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)  # Проверяем, что категория не найдена

    def test_delete_category_unauthenticated(self):
        category = Category.objects.create(name='Category to Delete')
        url_delete = reverse('category-detail', args=[category.id])  # URL для удаления категории

        response = self.client.delete(url_delete)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)  # Проверяем, что доступ запрещен

class CategoryViewSetTests(APITestCase):

    def setUp(self):
        self.admin_user = User.objects.create_user(
            username='adminuser',
            email='admin@example.com',
            password='adminpassword',
            is_staff=True,  # Устанавливаем пользователя как администратора
            is_superuser=True  # Устанавливаем пользователя как суперпользователя
        )
        self.normal_user = User.objects.create_user(
            username='normaluser',
            email='user@example.com',
            password='userpassword'
        )

        self.category = Category.objects.create(name='Test Category')
        self.url_retrieve = reverse('category-detail', args=[self.category.id])  # URL для получения категории
        self.url_update = reverse('category-detail', args=[self.category.id])  # URL для обновления категории
        self.url_delete = reverse('category-detail', args=[self.category.id])  # URL для удаления категории

    def test_retrieve_category(self):
        self.client.force_authenticate(user=self.normal_user)

        response = self.client.get(self.url_retrieve)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], 'Test Category')  # Проверяем, что данные корректные

    def test_update_category(self):
        self.client.force_authenticate(user=self.admin_user)

        updated_data = {
            'name': 'Updated Category'
        }

        response = self.client.put(self.url_update, updated_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.category.refresh_from_db()  # Обновляем объект из базы данных
        self.assertEqual(self.category.name, 'Updated Category')  # Проверяем, что имя обновилось

    def test_partial_update_category(self):
        self.client.force_authenticate(user=self.admin_user)

        updated_data = {
            'name': 'Partially Updated Category'
        }

        response = self.client.patch(self.url_update, updated_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.category.refresh_from_db()  # Обновляем объект из базы данных
        self.assertEqual(self.category.name, 'Partially Updated Category')  # Проверяем, что имя обновилось

    def test_delete_category_soft(self):
        self.client.force_authenticate(user=self.normal_user)

        response = self.client.delete(self.url_delete)

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)  # Проверяем, что категория мягко удалена
        self.category.refresh_from_db()  # Обновляем объект из базы данных
        self.assertTrue(self.category.deleted)  # Проверяем, что категория помечена как удаленная
        self.assertIsNotNone(self.category.deleted_at)  # Проверяем, что время удаления установлено


    def test_retrieve_nonexistent_category(self):
        self.client.force_authenticate(user=self.normal_user)

        nonexistent_url = reverse('category-detail', args=[9999])  # ID, который не существует
        response = self.client.get(nonexistent_url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)  # Проверяем, что категория не найдена

    def test_update_nonexistent_category(self):
        self.client.force_authenticate(user=self.admin_user)

        nonexistent_url = reverse('category-detail', args=[9999])  # ID, который не существует
        updated_data = {
            'name': 'Updated Nonexistent Category'
        }

        response = self.client.put(nonexistent_url, updated_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)  # Проверяем, что категория не найдена

    def test_delete_nonexistent_category(self):
        self.client.force_authenticate(user=self.admin_user)

        nonexistent_url = reverse('category-detail', args=[9999])  # ID, который не существует
        response = self.client.delete(nonexistent_url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)  # Проверяем, что категория не найдена

    def test_delete_category_unauthenticated(self):
        response = self.client.delete(self.url_delete)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)  # Проверяем, что доступ запрещен
















