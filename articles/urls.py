from django.urls import path, include
from . import views
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r'', views.ArticlesView, basename='articles')
router.register(r'comments', views.CommentsView, basename='comments')


urlpatterns = [
    path('articles/<int:id>/comments/', views.CreateCommentsView.as_view(), name='create_comments'),
    path('articles/<int:id>/detail/comments/', views.ArticleDetailCommentsView.as_view(), name='article-detail-comments'),
    path('articles/<int:pk>/favorite/', views.FavoriteArticleView.as_view(), name='favorite-article'),
    path('articles/<int:id>/report/', views.ReportArticleView.as_view(), name='report-article'),
    path('articles/faqs/', views.FAQListView.as_view(), name='faq-list'),  # Ensure this path is correct
    path('articles/topics/<int:id>/follow/', views.TopicFollowView.as_view(), name='topic-follow'),
    path('articles/<int:id>/clap/', views.ClapView.as_view(), name='article-clap'),
    path('articles/search/', views.SearchView.as_view(), name='article-search'),
    path('articles/', include(router.urls)),
]
