import cv2
import os
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
import hashlib
import time

# Create directory for encrypted images if it doesn't exist
FOLDER = "encrypted_images"
os.makedirs(FOLDER, exist_ok=True)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def hide_message(img_path, secret_text, passcode):
    image = cv2.imread(img_path)
    if image is None:
        messagebox.showerror("Error", "Invalid image file.")
        return
    
    encoded_text = hash_password(passcode) + '|' + secret_text
    text_length = len(encoded_text)
    
    if text_length + 1 > image.shape[0] * image.shape[1]:  
        messagebox.showerror("Error", "Message is too long for this image.")
        return
    
    image[0, 0, 0] = text_length  
    
    for index, char in enumerate(encoded_text):
        row, col = divmod(index + 1, image.shape[1])
        image[row, col, 0] = ord(char)
    
    timestamp = int(time.time())
    encrypted_path = os.path.join(FOLDER, f"secured_image_{timestamp}.png")
    cv2.imwrite(encrypted_path, image)
    messagebox.showinfo("Success", f"Encrypted image saved at:\n{encrypted_path}")

def reveal_message(img_path):
    entered_passcode = simpledialog.askstring("Input", "Enter Secret Passcode:", show="*")
    if not entered_passcode:
        return
    
    image = cv2.imread(img_path)
    if image is None:
        messagebox.showerror("Error", "Invalid image file.")
        return
    
    text_length = image[0, 0, 0]
    
    extracted_text = ''.join(
        chr(image[row, col, 0]) 
        for row, col in (divmod(i + 1, image.shape[1]) for i in range(text_length))
    )
    
    if '|' in extracted_text:
        saved_passcode, secret_message = extracted_text.split('|', 1)
        if saved_passcode == hash_password(entered_passcode):
            messagebox.showinfo("Decrypted Message", secret_message.strip())
        else:
            messagebox.showerror("Error", "Wrong passcode!")
    else:
        messagebox.showerror("Error", "Corrupted data or incorrect format.")

def browse_image(mode):
    img_file = filedialog.askopenfilename(title="Choose Image", filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
    if img_file:
        if mode == "encrypt":
            user_pass = key_input.get()
            if user_pass:
                hide_message(img_file, message_input.get(), user_pass)
            else:
                messagebox.showerror("Error", "Enter a passcode before encrypting.")
        elif mode == "decrypt":
            reveal_message(img_file)

app = tk.Tk()
app.title("Image Steganography Tool")
app.geometry("360x300")
app.configure(bg="#f0f0f0")

tk.Label(app, text="Steganography Tool", font=("Arial", 14, "bold"), bg="#f0f0f0").pack(pady=10)

frame = tk.Frame(app, bg="#ffffff", padx=10, pady=10)
frame.pack(pady=5, padx=15, fill="both", expand=True)

tk.Label(frame, text="Secret Message:", bg="#ffffff").grid(row=0, column=0, sticky="w", pady=5)
message_input = tk.Entry(frame, width=35)
message_input.grid(row=0, column=1, pady=5)

tk.Label(frame, text="Passcode:", bg="#ffffff").grid(row=1, column=0, sticky="w", pady=5)
key_input = tk.Entry(frame, width=35, show="*")
key_input.grid(row=1, column=1, pady=5)

btn_encrypt = tk.Button(app, text="Encrypt Image", command=lambda: browse_image("encrypt"), width=15, bg="#4CAF50", fg="white")
btn_encrypt.pack(pady=5)

btn_decrypt = tk.Button(app, text="Decrypt Image", command=lambda: browse_image("decrypt"), width=15, bg="#2196F3", fg="white")
btn_decrypt.pack(pady=5)

app.mainloop()
