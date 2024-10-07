#!/bin/sh

python manage.py migrate

echo "from django.contrib.auth import get_user_model; User = get_user_model(); User.objects.create_superuser('todo', 'todo@example.com', 'todo')" | python manage.py shell || true

python manage.py loaddata all_data

exec "$@"