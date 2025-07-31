import json
from collections import defaultdict

def prepare_chart_data(items):
    # Bar Chart: Stock per Category
    stock_per_category = defaultdict(int)
    for item in items:
        cat = item['category'] if item['category'] else 'Uncategorized'
        stock_per_category[cat] += item['quantity']
    bar_labels = list(stock_per_category.keys())
    bar_data = list(stock_per_category.values())

    # Pie Chart: Distribution of Units
    unit_distribution = defaultdict(int)
    for item in items:
        unit = item['unit'] if item['unit'] else 'Unknown'
        unit_distribution[unit] += 1
    pie_labels = list(unit_distribution.keys())
    pie_data = list(unit_distribution.values())

    # Return as JSON-serializable objects for Jinja/Chart.js
    return {
        "bar_labels": json.dumps(bar_labels),
        "bar_data": json.dumps(bar_data),
        "pie_labels": json.dumps(pie_labels),
        "pie_data": json.dumps(pie_data)
    }
