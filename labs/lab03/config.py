"""Параметри варіанта 8: облік часу відновлення сервісів."""

import sys

VARIANT_TITLE = "Облік часу відновлення сервісів"
DOMAIN_DESCRIPTION = (
    "Сервіс обліку навчальних вимірювань відновлення. Категорія визначає "
    "сервіс, value — час відновлення у хвилинах, status — стан перевірки "
    "вимірювання."
)

# Одиниця вимірювання value
UNIT = "minutes"
# Поріг: відновлення довше за 60 хв вважається повільним
THRESHOLD = 60.0

# Межі value: не менше 0, верхня межа лише відсікає нескінченність
VALUE_MIN = 0.0
VALUE_MAX = sys.float_info.max

STATUSES = ("new", "in_progress", "done")

# Обмеження довжин рядків (збігаються з CHECK у schema.sql)
CATEGORY_NAME_MIN = 2
CATEGORY_NAME_MAX = 40
CODE_MIN = 3
CODE_MAX = 40
TITLE_MIN = 3
TITLE_MAX = 120

# Поділ на сторінки та пакетне додавання
DEFAULT_LIMIT = 20
MAX_LIMIT = 100
BULK_MIN = 1
BULK_MAX = 100
