# Generated by Django 5.0.4 on 2024-07-09 06:17

from django.conf import settings
from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("articles", "0007_alter_recommendation_less"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name="topicfollow",
            unique_together={("user", "topic")},
        ),
    ]
