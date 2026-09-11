import json


def report_data(result):
    return result.model_dump(mode="json")


def render_json(result):
    return (
        json.dumps(report_data(result), ensure_ascii=True, sort_keys=True, indent=2)
        + "\n"
    )
