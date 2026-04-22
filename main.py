import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from tkinter.scrolledtext import ScrolledText
import random
from linear_congruential_generator import LinearCongruentialGenerator
from lcg_analysis import calculatePeriod, cesaroTest
from md5_core import MD5Hasher
from md5_file_utils import calculateFileMd5, saveHashToFile, verifyFileIntegrity
from rc5_file_utils import encrypt_file, decrypt_file
from rsa_file_utils import generate_rsa_keys, encrypt_file_rsa, decrypt_file_rsa
from dss_core import DSSigner
from dss_file_utils import signFile, verifyFileSignature, saveSignatureToFile, loadSignatureFromFile
import os
import time


def createApp():
    modulus = 2 ** 11 - 1
    multiplier = 35
    increment = 1
    seed = 4

    root = tk.Tk()
    root.title("Захист інформації – Лабораторні роботи")
    root.geometry("900x640")
    root.minsize(900, 640)
    root.configure(bg="#0f172a")

    style = ttk.Style()
    style.theme_use("clam")

    style.configure("App.TFrame", background="#0f172a")
    style.configure("Card.TFrame", background="#111827")
    style.configure("Top.TFrame", background="#0b1220")

    style.configure("Title.TLabel", background="#0b1220", foreground="#e5e7eb", font=("Segoe UI", 18, "bold"))
    style.configure("Sub.TLabel", background="#0b1220", foreground="#94a3b8", font=("Segoe UI", 11))

    style.configure("H1.TLabel", background="#111827", foreground="#e5e7eb", font=("Segoe UI", 16, "bold"))
    style.configure("P.TLabel", background="#111827", foreground="#cbd5e1", font=("Segoe UI", 11))
    style.configure("Meta.TLabel", background="#111827", foreground="#94a3b8", font=("Segoe UI", 10))

    style.configure("Primary.TButton", background="#2563eb", foreground="white", font=("Segoe UI", 11, "bold"), padding=10)
    style.map("Primary.TButton", background=[("active", "#1d4ed8")])

    style.configure("Ghost.TButton", background="#111827", foreground="#e5e7eb", font=("Segoe UI", 11), padding=10)
    style.map("Ghost.TButton", background=[("active", "#0b1220")])

    style.configure("Disabled.TButton", background="#111827", foreground="#64748b", font=("Segoe UI", 11), padding=10)

    style.configure("TEntry", fieldbackground="#0b1220", foreground="#e5e7eb", insertcolor="#e5e7eb")
    style.configure("TCombobox", fieldbackground="#0b1220", foreground="#e5e7eb")
    style.map("TEntry", fieldbackground=[("focus", "#0b1220")])

    activeLabs = {
        1: True,
        2: True,
        3: True,
        4: True,
        5: True
    }

    container = ttk.Frame(root, style="App.TFrame")
    container.pack(fill="both", expand=True)

    topBar = ttk.Frame(container, style="Top.TFrame", padding=(18, 14))
    topBar.pack(fill="x")

    ttk.Label(topBar, text="Захист інформації", style="Title.TLabel").pack(anchor="w")
    ttk.Label(topBar, text="Варіант №2", style="Sub.TLabel").pack(anchor="w", pady=(4, 0))

    content = ttk.Frame(container, style="App.TFrame", padding=(18, 18))
    content.pack(fill="both", expand=True)

    screens = {}

    def showScreen(name):
        for screenName in screens:
            screens[screenName].pack_forget()
        screens[name].pack(fill="both", expand=True)

    def buildMenuScreen():
        frame = ttk.Frame(content, style="App.TFrame")
        card = ttk.Frame(frame, style="Card.TFrame", padding=(18, 18))
        card.pack(fill="both", expand=True)

        ttk.Label(card, text="Головне меню", style="H1.TLabel").pack(anchor="w")
        ttk.Label(card, text="Обери лабораторну роботу. Неактивні пункти будуть недоступні.", style="P.TLabel").pack(anchor="w", pady=(6, 14))

        buttons = ttk.Frame(card, style="Card.TFrame")
        buttons.pack(fill="x")

        def addLabButton(labNumber, title, subtitle):
            labFrame = ttk.Frame(buttons, style="Card.TFrame", padding=(0, 0))
            labFrame.pack(fill="x", pady=6)

            left = ttk.Frame(labFrame, style="Card.TFrame")
            left.pack(side="left", fill="x", expand=True)

            ttk.Label(left, text=title, style="P.TLabel", font=("Segoe UI", 12, "bold")).pack(anchor="w")
            ttk.Label(left, text=subtitle, style="Meta.TLabel").pack(anchor="w", pady=(2, 0))

            isEnabled = activeLabs.get(labNumber, False)
            if isEnabled:
                btn = ttk.Button(labFrame, text="Відкрити", style="Primary.TButton", command=lambda: showScreen(f"lab{labNumber}"))
                btn.pack(side="right")
            else:
                btn = ttk.Button(labFrame, text="Недоступно", style="Disabled.TButton", state="disabled")
                btn.pack(side="right")

        addLabButton(1, "Лабораторна №1 – ГПВЧ", "Лінійний конгруентний генератор + період + тест Чезаро")
        addLabButton(2, "Лабораторна №2 – MD5", "Хешування текстів та файлів, перевірка цілісності")
        addLabButton(3, "Лабораторна №3 – RC5", "Шифрування файлів алгоритмом RC5-CBC-Pad")
        addLabButton(4, "Лабораторна №4 – RSA", "Асиметричне шифрування та порівняння швидкості")
        addLabButton(5, "Лабораторна №5 – DSS", "Цифровий підпис за стандартом DSS")

        footer = ttk.Frame(card, style="Card.TFrame")
        footer.pack(fill="x", pady=(18, 0))

        return frame

    def buildLab1Screen():
        frame = ttk.Frame(content, style="App.TFrame")

        card = ttk.Frame(frame, style="Card.TFrame", padding=(18, 18))
        card.pack(fill="both", expand=True)

        lastGeneratedNumbers = None
        lastPiEstimate = None

        headerRow = ttk.Frame(card, style="Card.TFrame")
        headerRow.pack(fill="x")

        ttk.Label(headerRow, text="Лабораторна №1 – ГПВЧ", style="H1.TLabel").pack(side="left", anchor="w")
        ttk.Button(headerRow, text="Назад у меню", style="Ghost.TButton", command=lambda: showScreen("menu")).pack(side="right")

        ttk.Label(card, text=f"Параметри варіанта: m={modulus}, a={multiplier}, c={increment}, x0={seed}", style="Meta.TLabel").pack(anchor="w", pady=(6, 12))

        inputRow = ttk.Frame(card, style="Card.TFrame")
        inputRow.pack(fill="x")

        countFrame = ttk.Frame(inputRow, style="Card.TFrame")
        countFrame.pack(side="left", padx=(0, 12))

        ttk.Label(countFrame, text="Кількість чисел для виводу", style="P.TLabel").pack(anchor="w")
        countEntry = ttk.Entry(countFrame, width=18)
        countEntry.pack(anchor="w", pady=(6, 0))
        countEntry.insert(0, "10")

        pairsFrame = ttk.Frame(inputRow, style="Card.TFrame")
        pairsFrame.pack(side="left", padx=(0, 12))

        ttk.Label(pairsFrame, text="Кількість пар для тесту Чезаро", style="P.TLabel").pack(anchor="w")
        pairsEntry = ttk.Entry(pairsFrame, width=22)
        pairsEntry.pack(anchor="w", pady=(6, 0))
        pairsEntry.insert(0, "10000")

        outputFrame = ttk.Frame(card, style="Card.TFrame")
        outputFrame.pack(fill="both", expand=True, pady=(14, 10))

        outputText = ScrolledText(outputFrame, wrap="word", height=16, font=("Consolas", 10), bg="#0b1220", fg="#e5e7eb", insertbackground="#e5e7eb", borderwidth=0)
        outputText.pack(fill="both", expand=True)

        def parsePositiveInt(value, defaultValue):
            try:
                parsed = int(str(value).strip())
                if parsed <= 0:
                    return defaultValue
                return parsed
            except Exception:
                return defaultValue

        def formatNumbersLine(numbers):
            display = numbers if len(numbers) <= 100 else numbers[:100]
            line = ", ".join(str(x) for x in display)
            if len(numbers) > 100:
                line += f", … (усього {len(numbers)})"
            return line

        def generateReport():
            nonlocal lastGeneratedNumbers, lastPiEstimate
            countValue = parsePositiveInt(countEntry.get(), 10)
            pairsValue = parsePositiveInt(pairsEntry.get(), 10000)

            genDisplay = LinearCongruentialGenerator(modulus, multiplier, increment, seed)
            numbersDisplay = genDisplay.generate(countValue)

            genPeriod = LinearCongruentialGenerator(modulus, multiplier, increment, seed)
            periodValue = calculatePeriod(genPeriod)

            genTest = LinearCongruentialGenerator(modulus, multiplier, increment, seed)
            numbersTest = genTest.generate(pairsValue * 2)
            probability, piEstimate = cesaroTest(numbersTest)

            lastGeneratedNumbers = numbersTest
            lastPiEstimate = piEstimate

            systemNumbers = [random.randint(0, modulus - 1) for _ in range(pairsValue * 2)]
            sysProbability, sysPi = cesaroTest(systemNumbers)

            lines = []
            lines.append("ЛР №1: Генератор псевдовипадкових чисел (LCG)")
            lines.append("")
            lines.append(f"Параметри: m={modulus}, a={multiplier}, c={increment}, x0={seed}")
            lines.append(f"Період генератора: {periodValue}")
            lines.append("")
            lines.append(f"Числа для виводу ({len(numbersDisplay)} шт.):")
            lines.append(formatNumbersLine(numbersDisplay))
            lines.append("")
            lines.append(f"Тест Чезаро (пари: {pairsValue})")
            lines.append(f"Ймовірність gcd=1 (LCG): {probability}")
            lines.append(f"Оцінка π (LCG): {piEstimate}")
            lines.append("")
            lines.append("Порівняння з системним генератором Python")
            lines.append(f"Ймовірність gcd=1 (system): {sysProbability}")
            lines.append(f"Оцінка π (system): {sysPi}")

            outputText.delete("1.0", tk.END)
            outputText.insert(tk.END, "\n".join(lines))

        def saveToFile():
            if not lastGeneratedNumbers or lastPiEstimate is None:
                messagebox.showinfo("Збереження", "Немає даних для збереження.")
                return
            path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Текстові файли", "*.txt"), ("Усі файли", "*.*")])
            if not path:
                return
            with open(path, "w", encoding="utf-8") as file:
                file.write("\n".join(str(x) for x in lastGeneratedNumbers) + "\n")
                file.write(str(lastPiEstimate) + "\n")
            messagebox.showinfo("Збереження", "Файл успішно збережено.")

        def clearOutput():
            outputText.delete("1.0", tk.END)

        btnRow = ttk.Frame(card, style="Card.TFrame")
        btnRow.pack(fill="x")

        ttk.Button(btnRow, text="Згенерувати", style="Primary.TButton", command=generateReport).pack(side="left")
        ttk.Button(btnRow, text="Зберегти у файл", style="Ghost.TButton", command=saveToFile).pack(side="left", padx=(10, 0))
        ttk.Button(btnRow, text="Очистити", style="Ghost.TButton", command=clearOutput).pack(side="left", padx=(10, 0))

        return frame

    def buildPlaceholderScreen(titleText, descriptionText):
        frame = ttk.Frame(content, style="App.TFrame")
        card = ttk.Frame(frame, style="Card.TFrame", padding=(18, 18))
        card.pack(fill="both", expand=True)

        headerRow = ttk.Frame(card, style="Card.TFrame")
        headerRow.pack(fill="x")

        ttk.Label(headerRow, text=titleText, style="H1.TLabel").pack(side="left", anchor="w")
        ttk.Button(headerRow, text="Назад у меню", style="Ghost.TButton", command=lambda: showScreen("menu")).pack(side="right")

        ttk.Label(card, text=descriptionText, style="P.TLabel").pack(anchor="w", pady=(10, 0))
        ttk.Label(card, text="Цей розділ буде активним після реалізації лабораторної.", style="Meta.TLabel").pack(anchor="w", pady=(6, 0))

        return frame

    def buildLab2Screen():
        frame = ttk.Frame(content, style="App.TFrame")
        card = ttk.Frame(frame, style="Card.TFrame", padding=(18, 18))
        card.pack(fill="both", expand=True)

        headerRow = ttk.Frame(card, style="Card.TFrame")
        headerRow.pack(fill="x")

        ttk.Label(headerRow, text="Лабораторна №2 – MD5", style="H1.TLabel").pack(side="left", anchor="w")
        ttk.Button(headerRow, text="Назад у меню", style="Ghost.TButton", command=lambda: showScreen("menu")).pack(side="right")

        hasher = MD5Hasher()
        
        # --- Текст ---
        textSection = ttk.Frame(card, style="Card.TFrame")
        textSection.pack(fill="x", pady=(15, 0))
        ttk.Label(textSection, text="1. Хешування та перевірка тексту", style="P.TLabel", font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(0, 5))
        
        textInputFrame = ttk.Frame(textSection, style="Card.TFrame")
        textInputFrame.pack(fill="x")
        ttk.Label(textInputFrame, text="Текст:", width=15, style="P.TLabel").pack(side="left")
        textEntry = ttk.Entry(textInputFrame)
        textEntry.pack(side="left", fill="x", expand=True, padx=(5, 10))
        
        def hashTextContent():
            txt = textEntry.get()
            res = hasher.hashString(txt)
            outputText.insert(tk.END, f"MD5 (текст): '{txt}' -> {res}\n")
            outputText.see(tk.END)
            
        ttk.Button(textInputFrame, text="Хешувати текст", style="Primary.TButton", command=hashTextContent).pack(side="left")
        
        textVerifyFrame = ttk.Frame(textSection, style="Card.TFrame")
        textVerifyFrame.pack(fill="x", pady=(5,0))
        ttk.Label(textVerifyFrame, text="Очікуваний MD5:", width=15, style="P.TLabel").pack(side="left")
        expectedTextEntry = ttk.Entry(textVerifyFrame)
        expectedTextEntry.pack(side="left", fill="x", expand=True, padx=(5, 10))
        
        def verifyTextContent():
            txt = textEntry.get()
            expected = expectedTextEntry.get().strip().upper()
            if not expected:
                messagebox.showerror("Помилка", "Введіть очікуваний хеш")
                return
            actual = hasher.hashString(txt)
            if expected == actual:
                outputText.insert(tk.END, f"✅ Текст ВІРНИЙ! MD5 збігається: {actual}\n")
            else:
                outputText.insert(tk.END, f"❌ ПОМИЛКА! Текст змінено.\nОчікувано: {expected}\nОтримано:  {actual}\n")
            outputText.see(tk.END)
            
        ttk.Button(textVerifyFrame, text="Перевірити текст", style="Ghost.TButton", command=verifyTextContent).pack(side="left")

        # --- Файл ---
        fileSection = ttk.Frame(card, style="Card.TFrame")
        fileSection.pack(fill="x", pady=(20, 0))
        ttk.Label(fileSection, text="2. Хешування та перевірка файлу", style="P.TLabel", font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(0, 5))
        
        selectedFile = tk.StringVar(value="")
        
        def selectFile():
            path = filedialog.askopenfilename(title="Виберіть файл")
            if path:
                selectedFile.set(path)
                
        fileTopFrame = ttk.Frame(fileSection, style="Card.TFrame")
        fileTopFrame.pack(fill="x")
        ttk.Button(fileTopFrame, text="Вибрати файл", style="Ghost.TButton", command=selectFile).pack(side="left")
        ttk.Label(fileTopFrame, textvariable=selectedFile, style="P.TLabel", foreground="#94a3b8").pack(side="left", padx=(10, 0))
        
        fileActionFrame = ttk.Frame(fileSection, style="Card.TFrame")
        fileActionFrame.pack(fill="x", pady=(5,0))
        
        def hashFileContent():
            path = selectedFile.get()
            if not path:
                messagebox.showerror("Помилка", "Спочатку виберіть файл")
                return
            try:
                res = calculateFileMd5(path)
                outputText.insert(tk.END, f"MD5 (файл): '{path}' ->\n{res}\n")
                outputText.see(tk.END)
            except Exception as e:
                messagebox.showerror("Помилка", f"Помилка читання файлу: {e}")
                
        ttk.Button(fileActionFrame, text="Хешувати файл", style="Primary.TButton", command=hashFileContent).pack(side="left")

        fileVerifyFrame = ttk.Frame(fileSection, style="Card.TFrame")
        fileVerifyFrame.pack(fill="x", pady=(5,0))
        ttk.Label(fileVerifyFrame, text="Очікуваний MD5:", width=15, style="P.TLabel").pack(side="left")
        expectedFileEntry = ttk.Entry(fileVerifyFrame)
        expectedFileEntry.pack(side="left", fill="x", expand=True, padx=(5, 10))

        def verifyFileContent():
            path = selectedFile.get()
            expected = expectedFileEntry.get().strip().upper()
            if not path:
                messagebox.showerror("Помилка", "Спочатку виберіть файл")
                return
            if not expected:
                messagebox.showerror("Помилка", "Введіть очікуваний хеш")
                return
                
            try:
                actual = calculateFileMd5(path)
                if expected == actual:
                    outputText.insert(tk.END, f"✅ Файл ЦІЛІСНИЙ! MD5 збігається.\n")
                else:
                    outputText.insert(tk.END, f"❌ ЦІЛІСНІСТЬ ПОРУШЕНО!\nОчікувано: {expected}\nОтримано:  {actual}\n")
                outputText.see(tk.END)
            except Exception as e:
                messagebox.showerror("Помилка", f"Помилка читання файлу: {e}")
                
        ttk.Button(fileVerifyFrame, text="Перевірити файл", style="Ghost.TButton", command=verifyFileContent).pack(side="left")

        # --- Результати ---
        ttk.Label(card, text="Результати:", style="P.TLabel", font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(20, 5))
        
        outputFrame = ttk.Frame(card, style="Card.TFrame")
        outputFrame.pack(fill="both", expand=True)

        outputText = ScrolledText(outputFrame, wrap="word", height=8, font=("Consolas", 10), bg="#0b1220", fg="#e5e7eb", insertbackground="#e5e7eb", borderwidth=0)
        outputText.pack(fill="both", expand=True)
        
        btnRow = ttk.Frame(card, style="Card.TFrame")
        btnRow.pack(fill="x", pady=(10, 0))
        ttk.Button(btnRow, text="Очистити", style="Ghost.TButton", command=lambda: outputText.delete("1.0", tk.END)).pack(side="left")
        
        def saveLogToFile():
            txt = outputText.get("1.0", tk.END).strip()
            if not txt:
                messagebox.showinfo("Збереження", "Немає результатів для збереження.")
                return
            path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Текстові файли", "*.txt"), ("Усі файли", "*.*")])
            if path:
                with open(path, "w", encoding="utf-8") as file:
                    file.write(txt)
                messagebox.showinfo("Збереження", "Результати збережено.")
                
        ttk.Button(btnRow, text="Зберегти результат у файл", style="Ghost.TButton", command=saveLogToFile).pack(side="left", padx=(10, 0))

        return frame
        
    def buildLab3Screen():
        frame = ttk.Frame(content, style="App.TFrame")
        card = ttk.Frame(frame, style="Card.TFrame", padding=(18, 18))
        card.pack(fill="both", expand=True)

        headerRow = ttk.Frame(card, style="Card.TFrame")
        headerRow.pack(fill="x")

        ttk.Label(headerRow, text="Лабораторна №3 – RC5", style="H1.TLabel").pack(side="left", anchor="w")
        ttk.Button(headerRow, text="Назад у меню", style="Ghost.TButton", command=lambda: showScreen("menu")).pack(side="right")

        ttk.Label(card, text="Варіант 2: w=32, r=12, b=16", style="Sub.TLabel").pack(anchor="w", pady=(8, 12))

        hasher = MD5Hasher()
        
        # --- Налаштування ---
        configSection = ttk.Frame(card, style="Card.TFrame")
        configSection.pack(fill="x", pady=(15, 0))
        ttk.Label(configSection, text="1. Налаштування шифрування", style="P.TLabel", font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(0, 5))
        
        passphraseFrame = ttk.Frame(configSection, style="Card.TFrame")
        passphraseFrame.pack(fill="x")
        ttk.Label(passphraseFrame, text="Парольна фраза:", width=18, style="P.TLabel").pack(side="left")
        passphraseEntry = ttk.Entry(passphraseFrame)
        passphraseEntry.pack(side="left", fill="x", expand=True, padx=(5, 10))

        # --- Файл ---
        fileSection = ttk.Frame(card, style="Card.TFrame")
        fileSection.pack(fill="x", pady=(20, 0))
        ttk.Label(fileSection, text="2. Робота з файлом", style="P.TLabel", font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(0, 5))
        
        selectedFile = tk.StringVar(value="")
        
        def selectFile():
            path = filedialog.askopenfilename(title="Виберіть файл")
            if path:
                selectedFile.set(path)
                
        fileTopFrame = ttk.Frame(fileSection, style="Card.TFrame")
        fileTopFrame.pack(fill="x")
        ttk.Button(fileTopFrame, text="Вибрати файл", style="Ghost.TButton", command=selectFile).pack(side="left")
        ttk.Label(fileTopFrame, textvariable=selectedFile, style="P.TLabel", foreground="#94a3b8").pack(side="left", padx=(10, 0))
        
        fileActionFrame = ttk.Frame(fileSection, style="Card.TFrame")
        fileActionFrame.pack(fill="x", pady=(10, 0))
        
        def run_encryption():
            passphrase = passphraseEntry.get()
            input_path = selectedFile.get()
            if not passphrase:
                messagebox.showerror("Помилка", "Введіть парольну фразу")
                return
            if not input_path:
                messagebox.showerror("Помилка", "Спочатку виберіть файл")
                return
            
            output_path = filedialog.asksaveasfilename(title="Зберегти зашифрований файл", defaultextension=".enc")
            if not output_path: return
            
            try:
                hex_hash = hasher.hashString(passphrase)
                key_bytes = bytes.fromhex(hex_hash)
                
                encrypt_file(input_path, output_path, key_bytes)
                outputText.insert(tk.END, f"✅ Зашифровано файл!\nВхідний: {input_path}\nВихідний: {output_path}\nMD5 хеш пароля: {hex_hash}\n\n")
                outputText.see(tk.END)
                messagebox.showinfo("Успіх", "Файл успішно зашифровано!")
            except Exception as e:
                messagebox.showerror("Помилка", f"Помилка шифрування: {e}")

        def run_decryption():
            passphrase = passphraseEntry.get()
            input_path = selectedFile.get()
            if not passphrase:
                messagebox.showerror("Помилка", "Введіть парольну фразу")
                return
            if not input_path:
                messagebox.showerror("Помилка", "Спочатку виберіть файл")
                return
            
            output_path = filedialog.asksaveasfilename(title="Зберегти розшифрований файл (НЕ ЗАБУДЬТЕ ДОДАТИ РОЗШИРЕННЯ, НАПРИКЛАД .pdf)")
            if not output_path: return
            
            import os
            if not os.path.splitext(output_path)[1]:
                messagebox.showwarning("Увага", "Ви не вказали розширення файлу (наприклад, .pdf, .txt, .jpg). Файл може не відкриватись автоматично, якщо Windows не знатиме його формат.")
            
            try:
                hex_hash = hasher.hashString(passphrase)
                key_bytes = bytes.fromhex(hex_hash)
                
                decrypt_file(input_path, output_path, key_bytes)
                outputText.insert(tk.END, f"✅ Розшифровано файл!\nВхідний: {input_path}\nВихідний: {output_path}\nMD5 хеш пароля: {hex_hash}\n\n")
                outputText.see(tk.END)
                messagebox.showinfo("Успіх", "Файл успішно розшифровано!")
            except Exception as e:
                messagebox.showerror("Помилка", f"Помилка розшифрування: {e}\nМожливо, невірний пароль або пошкоджено файл.")
                
        ttk.Button(fileActionFrame, text="Зашифрувати файл", style="Primary.TButton", command=run_encryption).pack(side="left")
        ttk.Button(fileActionFrame, text="Розшифрувати файл", style="Ghost.TButton", command=run_decryption).pack(side="left", padx=(10, 0))

        # --- Результати ---
        ttk.Label(card, text="Лог роботи:", style="P.TLabel", font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(20, 5))
        
        outputFrame = ttk.Frame(card, style="Card.TFrame")
        outputFrame.pack(fill="both", expand=True)

        outputText = ScrolledText(outputFrame, wrap="word", height=8, font=("Consolas", 10), bg="#0b1220", fg="#e5e7eb", insertbackground="#e5e7eb", borderwidth=0)
        outputText.pack(fill="both", expand=True)
        
        btnRow = ttk.Frame(card, style="Card.TFrame")
        btnRow.pack(fill="x", pady=(10, 0))
        ttk.Button(btnRow, text="Очистити лог", style="Ghost.TButton", command=lambda: outputText.delete("1.0", tk.END)).pack(side="left")
        
        return frame

    def buildLab4Screen():
        frame = ttk.Frame(content, style="App.TFrame")
        card = ttk.Frame(frame, style="Card.TFrame", padding=(18, 18))
        card.pack(fill="both", expand=True)

        headerRow = ttk.Frame(card, style="Card.TFrame")
        headerRow.pack(fill="x")

        ttk.Label(headerRow, text="Лабораторна №4 – RSA", style="H1.TLabel").pack(side="left", anchor="w")
        ttk.Button(headerRow, text="Назад у меню", style="Ghost.TButton", command=lambda: showScreen("menu")).pack(side="right")

        ttk.Label(card, text="Асиметричне шифрування (2048 біт) із розбиттям файлу", style="Sub.TLabel").pack(anchor="w", pady=(8, 12))

        # --- Генерація ключів ---
        keysSection = ttk.Frame(card, style="Card.TFrame")
        keysSection.pack(fill="x", pady=(10, 0))
        ttk.Label(keysSection, text="1. Генерація RSA ключів", style="P.TLabel", font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(0, 5))

        def run_key_generation():
            dir_path = filedialog.askdirectory(title="Виберіть папку для збереження ключів")
            if not dir_path: return
            
            priv_path = os.path.join(dir_path, "private_key.pem")
            pub_path = os.path.join(dir_path, "public_key.pem")
            try:
                generate_rsa_keys(priv_path, pub_path)
                outputText.insert(tk.END, f"✅ Ключі успішно згенеровано!\nПриватний: {priv_path}\nПублічний: {pub_path}\n\n")
                outputText.see(tk.END)
                messagebox.showinfo("Успіх", "Ключі RSA успішно згенеровано та збережено.")
            except Exception as e:
                messagebox.showerror("Помилка", f"Помилка створення ключів: {e}")

        ttk.Button(keysSection, text="Згенерувати пару ключів", style="Primary.TButton", command=run_key_generation).pack(anchor="w")

        # --- Файл ---
        fileSection = ttk.Frame(card, style="Card.TFrame")
        fileSection.pack(fill="x", pady=(15, 0))
        ttk.Label(fileSection, text="2. Шифрування та Дешифрування", style="P.TLabel", font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(0, 5))
        
        selectedFile = tk.StringVar(value="")
        selectedPubKey = tk.StringVar(value="")
        selectedPrivKey = tk.StringVar(value="")
        
        def selectFileVar(var, title="Виберіть файл"):
            path = filedialog.askopenfilename(title=title)
            if path: var.set(path)

        def make_file_selector(parent, text_label, var, btn_text):
            row = ttk.Frame(parent, style="Card.TFrame")
            row.pack(fill="x", pady=(2, 2))
            ttk.Label(row, text=text_label, width=20, style="P.TLabel").pack(side="left")
            ttk.Button(row, text=btn_text, style="Ghost.TButton", command=lambda: selectFileVar(var, btn_text)).pack(side="left", padx=(0, 10))
            ttk.Label(row, textvariable=var, style="P.TLabel", foreground="#94a3b8").pack(side="left")
            return row

        make_file_selector(fileSection, "Цільовий файл:", selectedFile, "Вибрати файл")
        make_file_selector(fileSection, "Публічний ключ (.pem):", selectedPubKey, "Вибрати публ. ключ")
        make_file_selector(fileSection, "Приватний ключ (.pem):", selectedPrivKey, "Вибрати прив. ключ")

        fileActionFrame = ttk.Frame(fileSection, style="Card.TFrame")
        fileActionFrame.pack(fill="x", pady=(10, 0))

        def run_rsa_encryption():
            input_path = selectedFile.get()
            pub_key = selectedPubKey.get()
            if not input_path or not pub_key:
                messagebox.showerror("Помилка", "Виберіть файл та публічний ключ")
                return
            output_path = filedialog.asksaveasfilename(title="Зберегти зашифрований файл", defaultextension=".enc")
            if not output_path: return
            try:
                start_time = time.time()
                encrypt_file_rsa(input_path, output_path, pub_key)
                elapsed = time.time() - start_time
                outputText.insert(tk.END, f"🔒 Зашифровано RSA (файл: {os.path.basename(input_path)}). Час: {elapsed:.4f} сек\n")
                outputText.see(tk.END)
                messagebox.showinfo("Успіх", f"Зашифровано! Час: {elapsed:.4f} с")
            except Exception as e:
                messagebox.showerror("Помилка", f"Помилка шифрування: {e}")

        def run_rsa_decryption():
            input_path = selectedFile.get()
            priv_key = selectedPrivKey.get()
            if not input_path or not priv_key:
                messagebox.showerror("Помилка", "Виберіть файл та приватний ключ")
                return
            output_path = filedialog.asksaveasfilename(title="Зберегти розшифрований файл")
            if not output_path: return
            try:
                start_time = time.time()
                decrypt_file_rsa(input_path, output_path, priv_key)
                elapsed = time.time() - start_time
                outputText.insert(tk.END, f"🔓 Дешифровано RSA (файл: {os.path.basename(input_path)}). Час: {elapsed:.4f} сек\n")
                outputText.see(tk.END)
                messagebox.showinfo("Успіх", f"Дешифровано! Час: {elapsed:.4f} с")
            except Exception as e:
                messagebox.showerror("Помилка", f"Помилка дешифрування: {e}")

        ttk.Button(fileActionFrame, text="Зашифрувати (RSA)", style="Primary.TButton", command=run_rsa_encryption).pack(side="left")
        ttk.Button(fileActionFrame, text="Розшифрувати (RSA)", style="Ghost.TButton", command=run_rsa_decryption).pack(side="left", padx=(10, 0))

        # --- Порівняння ---
        compareSection = ttk.Frame(card, style="Card.TFrame")
        compareSection.pack(fill="x", pady=(15, 0))
        ttk.Label(compareSection, text="3. Порівняння з RC5", style="P.TLabel", font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(0, 5))
        
        passphraseFrame = ttk.Frame(compareSection, style="Card.TFrame")
        passphraseFrame.pack(fill="x", pady=(0, 10))
        ttk.Label(passphraseFrame, text="Пароль для RC5:", width=18, style="P.TLabel").pack(side="left")
        passphraseEntry = ttk.Entry(passphraseFrame)
        passphraseEntry.pack(side="left", fill="x", expand=True, padx=(5, 10))
        passphraseEntry.insert(0, "testpassword")

        def run_speed_comparison():
            input_path = selectedFile.get()
            pub_key = selectedPubKey.get()
            passphrase = passphraseEntry.get()
            if not input_path or not pub_key or not passphrase:
                messagebox.showerror("Помилка", "Виберіть файл, публічний ключ (RSA) та введіть пароль (RC5)")
                return
            try:
                import tempfile
                import os
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                from cryptography.hazmat.backends import default_backend
                
                hasher = MD5Hasher()
                key_bytes = bytes.fromhex(hasher.hashString(passphrase))
                
                tmp_dir = tempfile.gettempdir()
                out_rsa = os.path.join(tmp_dir, "enc_rsa.tmp")
                out_rc5 = os.path.join(tmp_dir, "enc_rc5.tmp")
                out_aes = os.path.join(tmp_dir, "enc_aes.tmp")
                
                # Власний RC5
                start_rc5 = time.time()
                encrypt_file(input_path, out_rc5, key_bytes)
                time_rc5 = time.time() - start_rc5
                
                # Бібліотечний RSA
                start_rsa = time.time()
                encrypt_file_rsa(input_path, out_rsa, pub_key)
                time_rsa = time.time() - start_rsa

                # Бібліотечний симетричний (AES 128)
                start_aes = time.time()
                aes_key = key_bytes[:16]
                iv = bytes([0] * 16)
                cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                with open(input_path, 'rb') as fin, open(out_aes, 'wb') as fout:
                    while True:
                        chunk = fin.read(64 * 1024)
                        if not chunk: break
                        if len(chunk) % 16 != 0:
                            chunk += bytes([0] * (16 - (len(chunk) % 16)))
                        fout.write(encryptor.update(chunk))
                    fout.write(encryptor.finalize())
                time_aes = time.time() - start_aes

                if os.path.exists(input_path):
                    file_size = os.path.getsize(input_path) / 1024
                else: file_size = 0
                
                res = f"⏱ Порівняння швидкості шифрування (Файл: {file_size:.1f} KB)\n"
                res += f"  Власний RC5 (Python): {time_rc5:.4f} сек\n"
                res += f"  Бібліотечний RSA:     {time_rsa:.4f} сек\n"
                res += f"  Бібліотечний AES:     {time_aes:.4f} сек\n\n"
                
                outputText.insert(tk.END, res)
                outputText.see(tk.END)
                
            except Exception as e:
                messagebox.showerror("Помилка", f"Помилка при порівнянні: {e}")

        ttk.Button(compareSection, text="Порівняти швидкість шифрування", style="Ghost.TButton", command=run_speed_comparison).pack(anchor="w")

        # --- Результати ---
        ttk.Label(card, text="Лог роботи:", style="P.TLabel", font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(15, 5))
        
        outputFrame = ttk.Frame(card, style="Card.TFrame")
        outputFrame.pack(fill="both", expand=True)

        outputText = ScrolledText(outputFrame, wrap="word", height=8, font=("Consolas", 10), bg="#0b1220", fg="#e5e7eb", insertbackground="#e5e7eb", borderwidth=0)
        outputText.pack(fill="both", expand=True)
        
        ttk.Button(card, text="Очистити лог", style="Ghost.TButton", command=lambda: outputText.delete("1.0", tk.END)).pack(anchor="w", pady=(10, 0))
        
        return frame

    def buildLab5Screen():
        frame = ttk.Frame(content, style="App.TFrame")
        card = ttk.Frame(frame, style="Card.TFrame", padding=(18, 18))
        card.pack(fill="both", expand=True)

        headerRow = ttk.Frame(card, style="Card.TFrame")
        headerRow.pack(fill="x")

        ttk.Label(headerRow, text="Лабораторна №5 – Цифровий підпис DSS", style="H1.TLabel").pack(side="left", anchor="w")
        ttk.Button(headerRow, text="Назад у меню", style="Ghost.TButton", command=lambda: showScreen("menu")).pack(side="right")

        ttk.Label(card, text="Створення та перевірка цифрового підпису за стандартом DSS", style="Sub.TLabel").pack(anchor="w", pady=(8, 12))

        # --- Генерація ключів ---
        keysSection = ttk.Frame(card, style="Card.TFrame")
        keysSection.pack(fill="x", pady=(10, 0))
        ttk.Label(keysSection, text="1. Генерація DSA ключів", style="P.TLabel", font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(0, 5))

        def run_key_generation():
            dir_path = filedialog.askdirectory(title="Виберіть папку для збереження ключів")
            if not dir_path: return
            
            priv_path = os.path.join(dir_path, "dsa_private_key.pem")
            pub_path = os.path.join(dir_path, "dsa_public_key.pem")
            try:
                signer = DSSigner()
                signer.generate_keys()
                signer.save_private_key(priv_path)
                signer.save_public_key(pub_path)
                outputText.insert(tk.END, f"✅ Ключі успішно згенеровано!\nПриватний: {priv_path}\nПублічний: {pub_path}\n\n")
                outputText.see(tk.END)
                messagebox.showinfo("Успіх", "Ключі DSA успішно згенеровано та збережено.")
            except Exception as e:
                messagebox.showerror("Помилка", f"Помилка створення ключів: {e}")

        ttk.Button(keysSection, text="Згенерувати пару ключів", style="Primary.TButton", command=run_key_generation).pack(anchor="w")

        # --- Робота з рядком ---
        strSection = ttk.Frame(card, style="Card.TFrame")
        strSection.pack(fill="x", pady=(15, 0))
        ttk.Label(strSection, text="2. Підписати / Перевірити рядок", style="P.TLabel", font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(0, 5))
        
        strInputFrame = ttk.Frame(strSection, style="Card.TFrame")
        strInputFrame.pack(fill="x")
        ttk.Label(strInputFrame, text="Рядок:", width=20, style="P.TLabel").pack(side="left")
        strEntry = ttk.Entry(strInputFrame)
        strEntry.pack(side="left", fill="x", expand=True, padx=(5, 10))

        strActionFrame = ttk.Frame(strSection, style="Card.TFrame")
        strActionFrame.pack(fill="x", pady=(5, 0))
        
        def run_str_sign():
            text = strEntry.get()
            priv_key = selectedPrivKey.get()
            if not text:
                messagebox.showerror("Помилка", "Введіть рядок")
                return
            if not priv_key:
                messagebox.showerror("Помилка", "Виберіть приватний ключ у розділі нижче")
                return
            try:
                signer = DSSigner()
                signer.load_private_key(priv_key)
                sig = signer.sign_data(text.encode('utf-8'))
                hex_sig = sig.hex().upper()
                outputText.insert(tk.END, f"✍️ Підпис рядка '{text}':\n{hex_sig}\n\n")
                outputText.see(tk.END)
            except Exception as e:
                messagebox.showerror("Помилка", f"Помилка підпису: {e}")

        def run_str_verify():
            text = strEntry.get()
            pub_key = selectedPubKey.get()
            # Питаємо підпис для перевірки
            sig_input = tk.simpledialog.askstring("Перевірка", "Введіть підпис (hex):")
            if not sig_input: return
            if not text:
                messagebox.showerror("Помилка", "Введіть рядок")
                return
            if not pub_key:
                messagebox.showerror("Помилка", "Виберіть публічний ключ у розділі нижче")
                return
            try:
                signer = DSSigner()
                signer.load_public_key(pub_key)
                sig_bytes = bytes.fromhex(sig_input)
                is_valid = signer.verify_data(text.encode('utf-8'), sig_bytes)
                if is_valid:
                    outputText.insert(tk.END, f"✅ Підпис рядка '{text}' ПРАВИЛЬНИЙ!\n\n")
                else:
                    outputText.insert(tk.END, f"❌ Підпис рядка '{text}' НЕПРАВИЛЬНИЙ!\n\n")
                outputText.see(tk.END)
            except Exception as e:
                messagebox.showerror("Помилка", f"Помилка перевірки: {e}")

        ttk.Button(strActionFrame, text="Підписати рядок", style="Primary.TButton", command=run_str_sign).pack(side="left")
        ttk.Button(strActionFrame, text="Перевірити підпис рядка", style="Ghost.TButton", command=run_str_verify).pack(side="left", padx=(10, 0))

        # --- Вибір ключів та файлів ---
        fileSection = ttk.Frame(card, style="Card.TFrame")
        fileSection.pack(fill="x", pady=(15, 0))
        ttk.Label(fileSection, text="3. Підписати / Перевірити файл", style="P.TLabel", font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(0, 5))
        
        selectedFile = tk.StringVar(value="")
        selectedPubKey = tk.StringVar(value="")
        selectedPrivKey = tk.StringVar(value="")
        
        def selectFileVar(var, title="Виберіть файл", filetypes=[("Усі файли", "*.*")]):
            path = filedialog.askopenfilename(title=title, filetypes=filetypes)
            if path: var.set(path)

        def make_file_selector(parent, text_label, var, btn_text):
            row = ttk.Frame(parent, style="Card.TFrame")
            row.pack(fill="x", pady=(2, 2))
            ttk.Label(row, text=text_label, width=20, style="P.TLabel").pack(side="left")
            ttk.Button(row, text=btn_text, style="Ghost.TButton", command=lambda: selectFileVar(var, btn_text)).pack(side="left", padx=(0, 10))
            ttk.Label(row, textvariable=var, style="P.TLabel", foreground="#94a3b8").pack(side="left")
            return row

        make_file_selector(fileSection, "Цільовий файл:", selectedFile, "Вибрати файл")
        make_file_selector(fileSection, "Публічний ключ (.pem):", selectedPubKey, "Вибрати публ. ключ")
        make_file_selector(fileSection, "Приватний ключ (.pem):", selectedPrivKey, "Вибрати прив. ключ")

        fileActionFrame = ttk.Frame(fileSection, style="Card.TFrame")
        fileActionFrame.pack(fill="x", pady=(10, 0))

        def run_file_sign():
            input_path = selectedFile.get()
            priv_key = selectedPrivKey.get()
            if not input_path or not priv_key:
                messagebox.showerror("Помилка", "Виберіть файл та приватний ключ")
                return
            output_path = filedialog.asksaveasfilename(title="Зберегти файл підпису", defaultextension=".sig")
            if not output_path: return
            try:
                signer = DSSigner()
                signer.load_private_key(priv_key)
                hex_sig = signFile(input_path, output_path, signer)
                outputText.insert(tk.END, f"✍️ Підписано файл: {os.path.basename(input_path)}\nПідпис збережено у: {output_path}\nHex: {hex_sig}\n\n")
                outputText.see(tk.END)
                messagebox.showinfo("Успіх", f"Файл підписано!")
            except Exception as e:
                messagebox.showerror("Помилка", f"Помилка підпису файлу: {e}")

        def run_file_verify():
            input_path = selectedFile.get()
            pub_key = selectedPubKey.get()
            if not input_path or not pub_key:
                messagebox.showerror("Помилка", "Виберіть файл та публічний ключ")
                return
            
            sig_path = filedialog.askopenfilename(title="Виберіть файл підпису (.sig)")
            if not sig_path: return
            
            try:
                signer = DSSigner()
                signer.load_public_key(pub_key)
                is_valid = verifyFileSignature(input_path, sig_path, signer)
                
                if is_valid:
                    outputText.insert(tk.END, f"✅ Підпис файлу ({os.path.basename(input_path)}) ПРАВИЛЬНИЙ!\n\n")
                    messagebox.showinfo("Перевірка", "Підпис ПРАВИЛЬНИЙ!")
                else:
                    outputText.insert(tk.END, f"❌ Підпис файлу ({os.path.basename(input_path)}) НЕПРАВИЛЬНИЙ!\n\n")
                    messagebox.showwarning("Перевірка", "Підпис НЕПРАВИЛЬНИЙ!")
                outputText.see(tk.END)
            except Exception as e:
                messagebox.showerror("Помилка", f"Помилка перевірки: {e}")

        ttk.Button(fileActionFrame, text="Підписати файл", style="Primary.TButton", command=run_file_sign).pack(side="left")
        ttk.Button(fileActionFrame, text="Перевірити підпис файлу", style="Ghost.TButton", command=run_file_verify).pack(side="left", padx=(10, 0))

        # --- Результати ---
        ttk.Label(card, text="Лог роботи:", style="P.TLabel", font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(15, 5))
        
        outputFrame = ttk.Frame(card, style="Card.TFrame")
        outputFrame.pack(fill="both", expand=True)

        outputText = ScrolledText(outputFrame, wrap="word", height=8, font=("Consolas", 10), bg="#0b1220", fg="#e5e7eb", insertbackground="#e5e7eb", borderwidth=0)
        outputText.pack(fill="both", expand=True)
        
        ttk.Button(card, text="Очистити лог", style="Ghost.TButton", command=lambda: outputText.delete("1.0", tk.END)).pack(anchor="w", pady=(10, 0))
        
        return frame

    screens["menu"] = buildMenuScreen()
    screens["lab1"] = buildLab1Screen()
    screens["lab2"] = buildLab2Screen()
    screens["lab3"] = buildLab3Screen()
    screens["lab4"] = buildLab4Screen()
    screens["lab5"] = buildLab5Screen()

    showScreen("menu")
    return root


def main():
    app = createApp()
    app.mainloop()


if __name__ == "__main__":
    main()