from celery.schedules import crontab

# redbeat_redis_url = "redis://127.0.0.1:6379/1"
# redbeat_lock_key = None

CELERY_IMPORTS = ('tasks.subdomain_enumeration')
CELERY_TASK_RESULT_EXPIRES = 30
CELERY_TIMEZONE = 'UTC'

CELERY_ACCEPT_CONTENT = ['json', 'msgpack', 'yaml']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'

# CELERYBEAT_SCHEDULE = {
#     'enum_domain': {
#         'task': 'tasks.subdomain_enumeration.enum_domain',
#         # Every minute
#         'schedule': crontab(minute="*"),
#     },
#     # enum each days
#     'enum_domain_daily': {
#     	'task': 'tasks.subdomain_enumeration.enum_domain_daily',
#     	'schedule': crontab(day="*")
#     }
# }

CELERY_RESULT_BACKEND = 'mongodb://192.168.33.10:27017/'
CELERY_MONGODB_BACKEND_SETTINGS = {
    'database': 'ThesisDB',
    'taskmeta_collection': 'taskmeta_collection',
}