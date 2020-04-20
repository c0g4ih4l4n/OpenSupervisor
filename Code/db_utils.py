import json

def cursor_to_json(cursor):
	response = []
	for item in cursor:
		item['_id'] = str(item['_id'])
		response.append(item)
	return response

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)