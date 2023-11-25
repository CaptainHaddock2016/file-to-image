import platform
from tkinter import messagebox

if not platform.system().lower().startswith("win"):
    messagebox.showerror("Unsupported Platform", "This platform isn't supported yet, this program only works on Microsoft Windows.")
    exit()
    
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import filedialog
import os.path
import api
import iconProvider
import utils
from PIL import ImageTk
from sys import platform
from tkinter import simpledialog

#iconProvider.get_icon("tet.zip", "large").show()

DEFAULT_RES = (1080, 720)

RES_OPTIONS = ["320x240", "640x480", "1080x720", "1920x1080", "2560x1440", "3840x2160", "7680x4320"]

ENCRYPT_AND_PASSWORD = False

PLACEHOLDER_ON = True

RECOMMENDED_RES = None

RES_TABLE = {
    "128x96": (128, 96),
    "256x144": (256, 144),
    "320x240": (320, 240),
    "640x480": (640, 480),
    "1080x720": (1080, 720),
    "1920x1080": (1920, 1080),
    "2560x1440": (2560, 1440),
    "3840x2160": (3840, 2160),
    "7680x4320": (7680, 4320)
}

class PasswordDialog(simpledialog.Dialog):
    def body(self, master):
        ttk.Label(master, text="The file is encrypted. Please enter the password to decrypt:").grid(row=0, columnspan=2)
        self.password_entry = ttk.Entry(master, show='*', width=40)
        self.password_entry.grid(row=1, column=0, sticky='ew')

        # Button to toggle the visibility of the password
        self.view_button = ttk.Button(master, text="View", command=self.view_password)
        self.view_button.grid(row=1, column=1)
        return self.password_entry  # initial focus on the password entry field

    def view_password(self):
        # Toggle the visibility of the password entry content
        if self.password_entry.cget('show') == '*':
            self.password_entry.config(show='')
            self.view_button.config(text='Hide')
        else:
            self.password_entry.config(show='*')
            self.view_button.config(text='View')

    def apply(self):
        self.result = self.password_entry.get()  # You can use this result as needed

    def buttonbox(self):
        # Overriding the standard buttonbox to use ttk buttons.
        box = ttk.Frame(self)

        self.ok_button = ttk.Button(box, text="OK", width=10, command=self.ok, default=tk.ACTIVE)
        self.ok_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.cancel_button = ttk.Button(box, text="Cancel", width=10, command=self.cancel)
        self.cancel_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.bind("<Return>", self.ok)
        self.bind("<Escape>", self.cancel)

        box.pack()

def encode_from_file():
    global progress_var
    if not file_path_encode_image_entry.get():
        messagebox.showerror("Input Source File", "Please input a source file to encode!")
        return
    elif not save_dir_encode_image_entry.get():
        messagebox.showerror("Output Source Directory", "Please specify an output directory for the image(s) to be saved to.")
        return
    
        
    if not os.path.exists(file_path_encode_image_entry.get()):
        messagebox.showerror("Invalid Source File", "The program could not find the source file specified.")
        return
    if not os.path.exists(save_dir_encode_image_entry.get()):
        messagebox.showerror("Invalid Output Directory", "The program could not find the output directory specified.")
        return
    
    progress_var.set(0)
    progress_bar = ttk.Progressbar(encode_image_frame, orient="horizontal", length=200, mode="determinate", variable=progress_var, maximum=api.num_frames(file_path_encode_image_entry.get(), RES_TABLE[selected_res_var.get()]))
    encode_button_encode_image.grid_remove()
    progress_bar.grid(row=4, columnspan=3, padx=5, pady=5)
    root.update()
    
    password = None
    
    if ENCRYPT_AND_PASSWORD:
        password = password_entry.get()
    
    api.encode_file_in_images(file_path_encode_image_entry.get(), save_dir_encode_image_entry.get(), RES_TABLE[selected_res_var.get()], password=password, progressfunc=progress_step)
    
    progress_bar.grid_remove()
    encode_button_encode_image.grid(row=4, columnspan=3, padx=5, pady=5)
    
    messagebox.showinfo("Encoding Finished", "The file has been encoded successfully.")
    
def resource_path(relative):
    return os.path.join(
        os.environ.get(
            "_MEIPASS2",
            os.path.abspath(".")
        ),
        relative
    )
    
def progress_step():
    progress_var.set(progress_var.get() + 1)
    root.update_idletasks()
    
def browse_input_encode_image():
    global RECOMMENDED_RES
    path = filedialog.askopenfilename(defaultextension="png")
    if path:
        file_path_encode_image_var.set(path)
        file_path_encode_image_entry.delete(0, tk.END)
        file_path_encode_image_entry.insert(0, file_path_encode_image_var.get())
        
        file_size = os.path.getsize(path)
        
        for res in RES_OPTIONS:
            whres = res.split("x")
            maxforres = int(whres[0]) * int(whres[1])
            if maxforres*3 > file_size:
                res_picker_encode_image.set_menu(res, *RES_OPTIONS)
                RECOMMENDED_RES = res
                break
    
def browse_output_encode_image():
    path = filedialog.askdirectory(title="Save output as...")
    if path:
        file_dir_var.set(path)
        save_dir_encode_image_entry.delete(0, tk.END)
        save_dir_encode_image_entry.insert(0, file_dir_var.get())
        
# Function to toggle the visibility of the password entry
def toggle_password_entry():
    global ENCRYPT_AND_PASSWORD
    if encryptvar.get():
        if not password_entry.get() == '' and not PLACEHOLDER_ON:
            ENCRYPT_AND_PASSWORD = True
        password_entry.grid(row=3, column=1, padx=5, pady=2)
        see_button.grid(row=3, column=2, padx=5, pady=2)
        password_entry.config(show='')
    else:
        password_entry.grid_remove()
        see_button.grid_remove()
        ENCRYPT_AND_PASSWORD = False
        
def on_entry_click(event):
    global PLACEHOLDER_ON
    if PLACEHOLDER_ON:
        password_entry.delete(0, "end") # delete all the text in the entry
        password_entry.insert(0, '') #Insert blank for user input
        password_entry.config(show='*')

# Function to add placeholder text if nothing is entered
def on_focusout(event):
    global PLACEHOLDER_ON
    global ENCRYPT_AND_PASSWORD
    if password_entry.get() == '':
        password_entry.insert(0, 'Password')
        password_entry.config(show='')
        ENCRYPT_AND_PASSWORD = False
        PLACEHOLDER_ON = True
    else:
        ENCRYPT_AND_PASSWORD = True
        PLACEHOLDER_ON = False

def toggle_password():
    if password_entry.cget('show') == '' and not PLACEHOLDER_ON:
        password_entry.config(show='*')
    else:
        password_entry.config(show='')
        
def warn_user_res(event):
    if RECOMMENDED_RES:
        if RES_OPTIONS.index(selected_res_var.get()) < RES_OPTIONS.index(RECOMMENDED_RES):
            messagebox.showwarning("Change resolution", "Setting the resolution lower than the recommended resolution will result in multiple images being outputted and possible decoding problems.")
        elif RES_OPTIONS.index(selected_res_var.get()) > RES_OPTIONS.index(RECOMMENDED_RES):
            messagebox.showwarning("Change resolution", "Setting the resolution higher than the recommended resolution will result in much unused space in the image.")
            

# Function to handle encoding from URL
root = tk.Tk()
root.resizable(False,False)

root.iconphoto(False, tk.PhotoImage(file=os.path.join(resource_path("icon.png"))))

progress_var = tk.DoubleVar()

root.title("File Encoder/Decoder")

# Create a notebook for tabs
notebook = ttk.Notebook(root)
notebook.pack(fill='both', expand=True)

# Create frames for each tab
encode_image_frame = ttk.Frame(notebook)
decode_image_frame = ttk.Frame(notebook)
# ... other frames ...

# Add frames to notebook
notebook.add(encode_image_frame, text='Encode to Image')
notebook.add(decode_image_frame, text='Decode from Image')
# ... other tabs ...

# ENCODE TO IMAGE
file_path_encode_image_var = tk.StringVar()
file_path_encode_image_label = ttk.Label(encode_image_frame, text="File Path To Encode")
file_path_encode_image_entry = ttk.Entry(encode_image_frame, width=50)
file_path_encode_image_button = ttk.Button(encode_image_frame, text="Browse", command=browse_input_encode_image)

file_dir_var = tk.StringVar()
save_dir_encode_image_label = ttk.Label(encode_image_frame, text="Output Directory")
save_dir_encode_image_entry = ttk.Entry(encode_image_frame, width=50)
save_dir_encode_image_button = ttk.Button(encode_image_frame, text="Browse", command=browse_output_encode_image)

selected_res_var = tk.StringVar()
res_picker_encode_image_label = ttk.Label(encode_image_frame, text="Image Resulution")
res_picker_encode_image = ttk.OptionMenu(encode_image_frame, selected_res_var, RES_OPTIONS[4], *RES_OPTIONS, command=warn_user_res)

encryptvar = tk.BooleanVar()
encryptvar.set(False)
encrypt_tick = ttk.Checkbutton(encode_image_frame, text="Encrypt", variable=encryptvar, command=toggle_password_entry)

encode_button_encode_image = ttk.Button(encode_image_frame, text="Encode", command=encode_from_file)

password_entry = ttk.Entry(encode_image_frame, width=50)
password_entry.insert(0, 'Password')
password_entry.bind('<FocusIn>', on_entry_click)
password_entry.bind('<FocusOut>', on_focusout)
password_entry.grid_remove()

see_button = ttk.Button(encode_image_frame, text='View', command=toggle_password)

file_path_encode_image_label.grid(row=0, column=0, padx=5, pady=5)
file_path_encode_image_entry.grid(row=0, column=1, padx=5, pady=5)
file_path_encode_image_button.grid(row=0, column=2, padx=5, pady=5)

save_dir_encode_image_label.grid(row=1, column=0, padx=5, pady=5)
save_dir_encode_image_entry.grid(row=1, column=1, padx=5, pady=5)
save_dir_encode_image_button.grid(row=1, column=2, padx=5, pady=5)

res_picker_encode_image_label.grid(row=2, column=0, padx=5, pady=5)
res_picker_encode_image.grid(row=2, column=1, padx=5, pady=5, sticky="w")

encrypt_tick.grid(row=3, column=0, padx=(0, 35), pady=5)

encode_button_encode_image.grid(row=4, columnspan=3, padx=5, pady=5)

# DECODE TO IMAGE

def browse_input_decode_image():
    path = filedialog.askdirectory()
    print(path)
    if path:
        file_path_decode_image_var.set(path)
        file_path_decode_image_entry.delete(0, tk.END)
        file_path_decode_image_entry.insert(0, file_path_decode_image_var.get())
        
def retrieve_from_file():
    global image, headerinfo, decodebutton
    
    headerinfo = api.get_header_from_image(file_path_decode_image_var.get())
    image = ImageTk.PhotoImage(iconProvider.get_icon(headerinfo[0], "large").resize((48, 48)))
    label = ttk.Label(decode_image_frame, image=image)
    label.grid(row=1, column=0, padx=5, pady=5)
    
    fnamelabel = ttk.Label(decode_image_frame, text=utils.shorten_filename(headerinfo[0], 38) + "\nFile size: " + utils.bytes_to_human_readable(headerinfo[2]) + f"\tEncrypted: {bool(headerinfo[3])}")
    fnamelabel.grid(row=1, column=1, padx=0, pady=5, sticky="w")
    
    decodebutton = ttk.Button(decode_image_frame, text="Decode", command=decode_from_image)
    decodebutton.grid(row=1, column=2, padx=5, pady=5)
        
    root.update()
    
def decode_from_image():

    password = None
    if bool(headerinfo[3]):
        pd = PasswordDialog(root, title="Password needed")
        password = pd.result
        print(password)
        
    saveloc = filedialog.asksaveasfilename(initialfile=headerinfo[0])
    
    progress_var.set(0)
    progress_bar = ttk.Progressbar(decode_image_frame, orient="horizontal", length=200, mode="determinate", variable=progress_var, maximum=api.num_frames_decode(file_path_decode_image_var.get()))
    progress_bar.grid(row=2, columnspan=3, padx=5, pady=5)
    decodebutton.grid_remove()
    root.update()
        
    try:
        result = api.decode_file_from_images(file_path_decode_image_var.get(), saveloc, password, progress_step)
    except:
        messagebox.showerror("Decoding Error", "There was a problem decoding the file.")
    
    decodebutton.grid(row=1, column=2, padx=5, pady=5)
    progress_bar.grid_remove()
    root.update()
    
    if result == False:
        messagebox.showerror("MAC check failed", "Could not decrypt the file, the file has been tampered with or the password is incorrect.")
        
    if result == True:
        messagebox.showinfo("Decoding Finished", "The file as been decoded successfully.")

file_path_decode_image_var = tk.StringVar()
file_path_decode_image_label = ttk.Label(decode_image_frame, text="Folder with Image(s)")
file_path_decode_image_entry = ttk.Entry(decode_image_frame, width=35)
file_path_decode_image_button = ttk.Button(decode_image_frame, text="Browse", command=browse_input_decode_image)

decode_button_encode_image = ttk.Button(decode_image_frame, text="Retrieve", command=retrieve_from_file)

file_path_decode_image_label.grid(row=0, column=0, padx=5, pady=5)
file_path_decode_image_entry.grid(row=0, column=1, padx=5, pady=5)
file_path_decode_image_button.grid(row=0, column=2, padx=5, pady=5)
decode_button_encode_image.grid(row=0, column=3, padx=5, pady=5)

# Run the application
root.mainloop()
