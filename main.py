import tkinter as tk
from tkinter import ttk, filedialog, messagebox, font
from datetime import datetime, timedelta
import pandas as pd
import re
import pytz
import socket

def get_hostname(ip):
    """Получение HostName по IP"""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return "Hostname Not Found"

def get_date_from_entry(entry):
    """"Получение даты из поля"""
    date_str = entry.get()
    try:
        date = datetime.strptime(date_str, "%d.%m.%Y").date()
        return date
    except ValueError:
        messagebox.showerror("Error", "Invalid date format")
        return None

def load_log_file():
    """Обработка загрузки файла и парсинг логов"""
    file_path = filedialog.askopenfilename()
    ip_text.delete('1.0', tk.END)
    if not file_path:
        return
    try:
        with open(file_path, 'r') as file:
            log_pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?)" (\d{3}) (\d+) "(.*?)" "(.*?)"'
            log_data = []
            for line in file:
                match = re.match(log_pattern, line)
                if match:
                    ip, datetime_str, request_str, status, size, referrer, user_agent = match.groups()
                    method, path, protocol = request_str.split()
                    datetime_obj = datetime.strptime(datetime_str, "%d/%b/%Y:%H:%M:%S %z")
                    log_data.append([ip, datetime_obj, path, status, user_agent])

            df = pd.DataFrame(log_data, columns=['IP', 'DateTime', 'Path', 'Status', 'UserAgent'])
            analyze_logs(df)
    except:
        messagebox.showerror("Error", "Could not read the file")

def analyze_logs(df):
    """Выборка логов по времени. Приведение к нужному формату и вызов обновлений GUI"""
    df['DateTime'] = df['DateTime'].dt.tz_convert(pytz.utc)

    start_date = get_date_from_entry(start_date_entry)
    start_time = start_time_entry.get()
    end_date = get_date_from_entry(end_date_entry)
    end_time = end_time_entry.get()

    if start_time and end_time:
        tz = pytz.utc
        start_datetime = datetime.combine(start_date, datetime.strptime(start_time, "%H:%M").time()).replace(tzinfo=tz)
        end_datetime = datetime.combine(end_date, datetime.strptime(end_time, "%H:%M").time()).replace(tzinfo=tz)
        df = df[(df['DateTime'] >= start_datetime) & (df['DateTime'] <= end_datetime)]

    total_requests = df.shape[0]
    total_requests_label.config(text=f"Total Requests: {total_requests}")
    total_unique_ips_label.config(text=f"Total Unique IPs: {df['IP'].nunique()}")

    ip_counts = df['IP'].value_counts().reset_index()
    ip_counts.columns = ['IP', 'Requests']
    ip_counts['Percentage'] = (ip_counts['Requests'] / total_requests * 100).round(2)
    ip_counts['Percentage'] = ip_counts['Percentage'].apply(lambda x: f"{x:.2f}%")

    update_ip_list(ip_counts)
    update_status_table(df)
    update_path_table(df)
    update_user_agent_table(df)


def format_for_clipboard(top_ips):
    """Генерация таблицы для копирования в биллинг"""
    headers = "| IP | Host | Requests | Check Host |"
    separator = "| --- | --- | --- | --- |"

    rows = []
    for _, row in top_ips.iterrows():
        ip = row['IP']
        host = row['Hostname']
        requests = str(row['Requests'])
        check_host = f"[Check Host](https://check-host.net/ip-info?host={ip})"
        rows.append(f"| {ip} | {host} | {requests} | {check_host} |")

    result = "\n".join([headers, separator] + rows)
    return result


def copy_top_ips():
    """Копирование таблицы в буфер обмена"""
    top_n = int(top_n_entry.get())
    if top_n == 0 or top_n <= 0:
        messagebox.showerror("Error", "Top IPs number must be an integer greater than 0")
        return
    top_ips = ip_counts.head(top_n)
    top_ips.loc[:, 'Hostname'] = top_ips['IP'].apply(get_hostname)
    formatted_text = format_for_clipboard(top_ips)
    root.clipboard_clear()
    root.clipboard_append(formatted_text)
    messagebox.showinfo("Success", "Data copied to clipboard")

def update_status_table(df):
    """Обновление таблицы со статусами"""
    for row in status_table.get_children():
        status_table.delete(row)
    status_counts = df['Status'].value_counts().reset_index()
    status_counts.columns = ['Status', 'Count']
    total_requests = sum(status_counts['Count'])

    for index, row in status_counts.iterrows():
        percent = (row['Count'] / total_requests * 100)
        status_table.insert("", tk.END, values=(row['Status'], row['Count'], f"{percent:.2f}%"))

def update_user_agent_table(df):
    """Обновление таблицы с User-agent"""
    user_agent_table.delete(*user_agent_table.get_children())
    user_agent_counts = df['UserAgent'].value_counts().reset_index()
    user_agent_counts.columns = ['UserAgent', 'Requests']
    total_requests = sum(user_agent_counts['Requests'])

    for index, row in user_agent_counts.iterrows():
        percent = (row['Requests'] / total_requests * 100) if total_requests > 0 else 0
        user_agent_table.insert("", tk.END, values=(row['UserAgent'], row['Requests'], f"{percent:.2f}%"))


def update_path_table(df):
    """Обновление таблицы с URL"""
    for row in path_table.get_children():
        path_table.delete(row)
    path_counts = df['Path'].value_counts().reset_index()
    path_counts.columns = ['Path', 'Requests']
    total_requests = sum(path_counts['Requests'])

    for index, row in path_counts.iterrows():
        percent = (row['Requests'] / total_requests * 100)
        path_table.insert("", tk.END, values=(row['Path'], row['Requests'], f"{percent:.2f}%"))

def copy_from_text(event):
    """Копирование из текстового поля с сортировкой IP"""

    try:
        root.clipboard_clear()
        root.clipboard_append(root.selection_get())
    except tk.TclError:
        pass

def copy_selected_rows(table):
    """Копирование из таблицы"""
    selected_items = table.selection()
    rows_data = []
    for item in selected_items:
        item_values = table.item(item, 'values')
        rows_data.append("\t".join(item_values))
    copied_text = "\n".join(rows_data)
    root.clipboard_clear()
    root.clipboard_append(copied_text)
    messagebox.showinfo("Success", "Selected rows copied to clipboard")

def tree_popup(event, menu):
    """Всплывающее меню для копирования из таблиц (в самих таблицах бинл на ПКМ)"""
    region = event.widget.identify_region(event.x, event.y)
    if region == "cell":
        menu.post(event.x_root, event.y_root)

def update_ip_list(data_frame):
    """Обновление текстового поля с отсортироваными по запросам IP"""
    global ip_counts
    ip_counts = data_frame
    ip_text.insert(tk.END, ip_counts.to_string(index=False))

def copy_selected_rows_status():
    """Копирование из таблицы статусов"""
    selected_ids = status_table.selection()  # Получаем ID всех выбранных элементов
    rows_data = []
    for item_id in selected_ids:
        item = status_table.item(item_id, 'values')
        rows_data.append("\t".join(item))  # Формируем строку значений для каждого элемента
    copied_text = "\n".join(rows_data)  # Соединяем все строки в одну строку, разделяя переводом строки
    root.clipboard_clear()
    root.clipboard_append(copied_text)  # Копируем строку в буфер обмена

def copy_selected_rows_path():
    """Копирование из таблицы URL"""
    selected_ids = path_table.selection()  # Получаем ID всех выбранных элементов
    rows_data = []
    for item_id in selected_ids:
        item = path_table.item(item_id, 'values')
        rows_data.append("\t".join(item))  # Формируем строку значений для каждого элемента
    copied_text = "\n".join(rows_data)  # Соединяем все строки в одну строку, разделяя переводом строки
    root.clipboard_clear()
    root.clipboard_append(copied_text)  # Копируем строку в буфер обмена

def copy_selected_rows_user():
    """Копирование из таблицы User-agent"""
    selected_ids = user_agent_table.selection()  # Получаем ID всех выбранных элементов
    rows_data = []
    for item_id in selected_ids:
        item = user_agent_table.item(item_id, 'values')
        rows_data.append("\t".join(item))  # Формируем строку значений для каждого элемента
    copied_text = "\n".join(rows_data)  # Соединяем все строки в одну строку, разделяя переводом строки
    root.clipboard_clear()
    root.clipboard_append(copied_text)  # Копируем строку в буфер обмена

#Визуал
root = tk.Tk()
root.title("Fozzy Log Analyzer")
root.geometry('700x900')

customFont = font.Font(family="Helvetica", size=16)

frame_center_date = tk.Frame(root)
frame_center_date.pack(pady=5)

frame_center_ips = tk.Frame(root)
frame_center_ips.pack(pady=5)

frame_date_time = tk.Frame(frame_center_date)
frame_date_time.pack(fill='x', pady=5)

frame_controls = tk.Frame(frame_center_ips)
frame_controls.pack(fill='x', padx=20, pady=5)

frame_tables = tk.Frame(root)
frame_tables.pack(fill='both', expand=True, padx=20, pady=5)

start_date_entry = tk.Entry(frame_date_time, width=16, borderwidth=2, font=customFont)
start_date_entry.insert(0, (datetime.now() - timedelta(days=1)).strftime("%d.%m.%Y"))
start_date_entry.grid(row=0, column=0, padx=5, pady=5)

start_time_entry = tk.Entry(frame_date_time, font=customFont, width=5, justify='center')
start_time_entry.insert(0, "00:00")
start_time_entry.grid(row=0, column=1, padx=5, pady=5)

end_date_entry = tk.Entry(frame_date_time, width=16, borderwidth=2, font=customFont)
end_date_entry.insert(0, datetime.now().strftime("%d.%m.%Y"))
end_date_entry.grid(row=1, column=0, padx=5, pady=5)

end_time_entry = tk.Entry(frame_date_time, font=customFont, width=5, justify='center')
end_time_entry.insert(0, datetime.now().strftime("%H:%M"))
end_time_entry.grid(row=1, column=1, padx=5, pady=5)

load_button = tk.Button(frame_date_time, text="Load Log File", command=load_log_file, font=customFont)
load_button.grid(row=1, column=2, padx=5, pady=5)

total_requests_label = tk.Label(frame_controls, text="Total Requests: 0", font=font.Font(family="Helvetica", size=16, weight="bold"))
total_requests_label.grid(row=1, column=0, padx=5)

total_unique_ips_label = tk.Label(frame_controls, text="Total Unique IPs: 0", font=font.Font(family="Helvetica", size=16, weight="bold"))
total_unique_ips_label.grid(row=2, column=0, padx=5, pady=5)

ip_text = tk.Text(frame_controls, height=10, width=50)
ip_text.grid(row = 3, column = 0)
ip_text.bind("<Control-c>", copy_from_text)

top_n_entry = tk.Entry(frame_controls, font=customFont, justify='center')
top_n_entry.insert(0, 10)
top_n_entry.grid(row=4, column=0, padx=5, pady=5)

copy_button = tk.Button(frame_controls, text="Copy Top IPs", command=copy_top_ips, font=customFont)
copy_button.grid(row=5, column=0, padx=5, pady=5)

tree_menu = tk.Menu(root, tearoff=0)
tree_menu.add_command(label="Copy From Status Table", command=copy_selected_rows_status)
tree_menu.add_command(label="Copy From Path Table", command=copy_selected_rows_path)
tree_menu.add_command(label="Copy From User Agent Table", command=copy_selected_rows_user)

tree_menu_status = tk.Menu(root, tearoff=0)
tree_menu_status.add_command(label="Copy", command=lambda: copy_selected_rows(status_table))

tree_menu_path = tk.Menu(root, tearoff=0)
tree_menu_path.add_command(label="Copy", command=lambda: copy_selected_rows(path_table))

tree_menu_user = tk.Menu(root, tearoff=0)
tree_menu_user.add_command(label="Copy", command=lambda: copy_selected_rows(user_agent_table))

status_table = ttk.Treeview(frame_tables, columns=("Status", "Count", "Percentage"), show="headings", height=5, selectmode='extended')
status_table.heading('Status', text='Status')
status_table.heading('Count', text='Count')
status_table.heading('Percentage', text='Percentage')
status_table.bind("<Button-2>", lambda event: tree_popup(event, tree_menu_status))  # Для Windows используйте <Button-3>, для macOS <Button-2>
status_table.pack(fill='both', expand=True, padx=5, pady=5)

path_table = ttk.Treeview(frame_tables, columns=("Path", "Requests", "Percentage"), show="headings", height=5, selectmode='extended')
path_table.heading('Path', text='Path')
path_table.heading('Requests', text='Requests')
path_table.heading('Percentage', text='Percentage')
path_table.bind("<Button-2>", lambda event: tree_popup(event, tree_menu_path))
path_table.pack(fill='both', expand=True, padx=5, pady=5)

user_agent_table = ttk.Treeview(frame_tables, columns=("UserAgent", "Count", "Percentage"), show="headings", height=5, selectmode='extended')
user_agent_table.heading('UserAgent', text='User Agent')
user_agent_table.heading('Count', text='Count')
user_agent_table.heading('Percentage', text='Percentage')
user_agent_table.bind("<Button-2>", lambda event: tree_popup(event, tree_menu_user))
user_agent_table.pack(fill='both', expand=True, padx=5, pady=5)


#Запуск приложения
try:
    root.mainloop()
except Exception as e:
    print(f"An error occurred: {e}")
    messagebox.showerror("Error", f"An error occurred: {e}")