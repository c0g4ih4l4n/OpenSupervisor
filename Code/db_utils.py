import json
import app

def cursor_to_json(cursor):
	response = []
	for item in cursor:
		item['_id'] = str(item['_id'])
		if 'subdomain_enum_task_id' in item:
			res = app.celery.AsyncResult(item['subdomain_enum_task_id'])
			item['task_status'] = res.status
		else: 
			item['task_status'] = 'No Task'
		response.append(item)
	return response

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)