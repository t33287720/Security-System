from datetime import datetime, timedelta
import requests

def get_index_range(days=2):
    dates = [(datetime.utcnow() - timedelta(days=i)).strftime("%Y.%m.%d") for i in range(days)]
    return [f"filebeat-{d}" for d in dates]


def get_existing_indices(requested_indices, ES_HOST, ES_USER, ES_PASS):
    url = f"{ES_HOST}/_cat/indices?h=index"
    try:
        resp = requests.get(url, auth=(ES_USER, ES_PASS), verify=False, timeout=(10, 60))
        resp.raise_for_status()
        indices = resp.text.strip().split('\n')
        return [idx for idx in requested_indices if idx in indices]
    except Exception as e:
        print(f"取得現有索引失敗: {e}")
        return []
    

def update_index_if_needed(state, ES_HOST, ES_USER, ES_PASS):
    """回傳 True 表示 index range 有變化（日期切換），False 表示無變化。"""
    current_date = datetime.utcnow().date()

    if state["stored_date"] != current_date:
        state["INDEX"] = get_index_range(2)
        state["stored_date"] = current_date
        print(f"更新索引: {','.join(state['INDEX'])}")
        return True

    return False


def search_new_logs(ES_HOST, ES_USER, ES_PASS, index_list, last_timestamp):
    if not index_list:
        return []

    index_str = ",".join(index_list)
    url = f"{ES_HOST}/{index_str}/_search"

    query = {
        "size": 200,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {
            "bool": {
                "must": [{"range": {"@timestamp": {"gt": last_timestamp}}}],
                "should": [
                    {"exists": {"field": "client_ip"}},
                    {"exists": {"field": "src_ip"}},
                    {"exists": {"field": "dst_ip"}}
                ],
                "minimum_should_match": 1
            }
        }
    }

    try:
        resp = requests.post(url, auth=(ES_USER, ES_PASS), json=query, verify=False, timeout=(10, 60))
        resp.raise_for_status()
        return resp.json().get("hits", {}).get("hits", [])
    except Exception as e:
        print(f"ES 查詢錯誤: {e}")
        return []