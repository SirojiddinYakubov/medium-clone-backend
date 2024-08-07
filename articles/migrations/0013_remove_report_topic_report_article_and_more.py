# Generated by Django 5.0.4 on 2024-07-15 12:27

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("articles", "0012_alter_recommendation_less_alter_recommendation_more"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.RemoveField(
            model_name="report",
            name="topic",
        ),
        migrations.AddField(
            model_name="report",
            name="article",
            field=models.ForeignKey(
                default=4,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="reports",
                to="articles.article",
            ),
            preserve_default=False,
        ),
        migrations.RemoveField(
            model_name="report",
            name="user",
        ),
        migrations.AddField(
            model_name="report",
            name="user",
            field=models.ManyToManyField(
                blank=True,
                limit_choices_to={"is_active": True},
                related_name="reports",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
    ]
