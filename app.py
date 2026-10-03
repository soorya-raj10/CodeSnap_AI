import streamlit as st
from google import genai
from google.genai import types
import time
import sqlite3
import hashlib
import secrets
import smtplib
from email.message import EmailMessage

# =====================================================
# PAGE SETTINGS
# =====================================================

st.set_page_config(
    page_title="CodeSnap AI",
    page_icon="</>",
    layout="wide"
)

# =====================================================
# DATABASE
# =====================================================

DB_FILE = "codesnap.db"

def get_connection():
    return sqlite3.connect(
        DB_FILE,
        check_same_thread=False
    )

def init_database():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            question TEXT NOT NULL,
            answer TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            analysis TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()

init_database()

# =====================================================
# PASSWORD SECURITY
# =====================================================

def hash_password(password):

    salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        100000
    )

    return salt.hex() + ":" + password_hash.hex()

def verify_password(password, stored_hash):

    try:

        salt_hex, hash_hex = stored_hash.split(":")
        salt = bytes.fromhex(salt_hex)

        password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            100000
        )

        return secrets.compare_digest(
            password_hash.hex(),
            hash_hex
        )

    except Exception:
        return False

# =====================================================
# USER MANAGEMENT
# =====================================================

def create_user(name, email, password):

    connection = get_connection()
    cursor = connection.cursor()

    try:

        cursor.execute(
            """
            INSERT INTO users
            (name, email, password_hash)
            VALUES (?, ?, ?)
            """,
            (
                name.strip(),
                email.strip().lower(),
                hash_password(password)
            )
        )

        connection.commit()
        user_id = cursor.lastrowid
        connection.close()

        return True, user_id, "Account created successfully."

    except sqlite3.IntegrityError:

        connection.close()

        return False, None, "This email is already registered."

    except Exception as error:

        connection.close()

        return False, None, str(error)

def authenticate_user(email, password):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id, name, email, password_hash
        FROM users
        WHERE email = ?
        """,
        (email.strip().lower(),)
    )

    user = cursor.fetchone()
    connection.close()

    if user is None:
        return None

    user_id, name, user_email, password_hash = user

    if verify_password(password, password_hash):

        return {
            "id": user_id,
            "name": name,
            "email": user_email
        }

    return None

def get_user(user_id):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id, name, email, created_at
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    )

    user = cursor.fetchone()
    connection.close()

    if user is None:
        return None

    return {
        "id": user[0],
        "name": user[1],
        "email": user[2],
        "created_at": user[3]
    }

# =====================================================
# SESSION STATE
# =====================================================

if "user" not in st.session_state:
    st.session_state.user = None

if "auth_page" not in st.session_state:
    st.session_state.auth_page = "login"

if "image_result" not in st.session_state:
    st.session_state.image_result = None

if "question_history" not in st.session_state:
    st.session_state.question_history = []

if "history_loaded" not in st.session_state:
    st.session_state.history_loaded = False

def logout_user():

    st.session_state.user = None
    st.session_state.image_result = None
    st.session_state.question_history = []
    st.session_state.history_loaded = False
    st.session_state.auth_page = "login"

    st.rerun()

# =====================================================
# GEMINI CLIENT
# =====================================================

@st.cache_resource
def get_client():

    return genai.Client(
        api_key=st.secrets["GEMINI_API_KEY"]
    )

client = get_client()

MODEL_NAME = "gemini-3.8-flash"

# =====================================================
# GEMINI RESPONSE FUNCTION
# =====================================================

def ask_gemini(prompt, image=None):

    contents = [prompt]

    if image is not None:

        image_part = types.Part.from_bytes(
            data=image.getvalue(),
            mime_type=image.type
        )

        contents.append(image_part)

    for attempt in range(3):

        try:

            response = client.models.generate_content(
                model=MODEL_NAME,
                contents=contents
            )

            if not response.text:
                raise ValueError("Gemini returned an empty response.")

            return response.text

        except Exception as error:

            error_message = str(error)

            if (
                "503" in error_message
                or "UNAVAILABLE" in error_message
            ):

                if attempt < 2:
                    time.sleep(2 ** attempt)
                    continue

                raise RuntimeError(
                    "Gemini is temporarily busy. Please try again."
                )

            raise RuntimeError(
                "Something went wrong: " + error_message
            )

# =====================================================
# CHAT HISTORY DATABASE FUNCTIONS
# =====================================================

def save_chat(user_id, question, answer):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO chat_history
        (user_id, question, answer)
        VALUES (?, ?, ?)
        """,
        (user_id, question, answer)
    )

    connection.commit()
    connection.close()

def load_chat_history(user_id):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT question, answer, created_at
        FROM chat_history
        WHERE user_id = ?
        ORDER BY id ASC
        """,
        (user_id,)
    )

    rows = cursor.fetchall()
    connection.close()

    return rows

def clear_chat_history(user_id):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        DELETE FROM chat_history
        WHERE user_id = ?
        """,
        (user_id,)
    )

    connection.commit()
    connection.close()

def save_analysis(user_id, analysis):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO analyses
        (user_id, analysis)
        VALUES (?, ?)
        """,
        (user_id, analysis)
    )

    connection.commit()
    connection.close()

# =====================================================
# EMAIL FUNCTION
# =====================================================

def send_email(recipient, subject, content):

    try:

        sender_email = st.secrets["EMAIL_ADDRESS"]
        sender_password = st.secrets["EMAIL_APP_PASSWORD"]

        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = sender_email
        message["To"] = recipient
        message.set_content(content)

        with smtplib.SMTP("smtp.gmail.com", 587) as server:

            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(message)

        return True, "Email sent successfully."

    except KeyError:

        return (
            False,
            "Email is not configured. Add EMAIL_ADDRESS "
            "and EMAIL_APP_PASSWORD to secrets.toml."
        )

    except Exception as error:

        return False, str(error)

# =====================================================
# CUSTOM CSS
# =====================================================

st.markdown("""
<style>

.stApp {
    background-color: #0b0f17;
    color: #f5f7fa;
}

.main-title {
    font-size: 58px;
    font-weight: 750;
    letter-spacing: -2.5px;
    margin-bottom: 4px;
}

.subtitle {
    font-size: 21px;
    color: #aab3c5;
    margin-bottom: 32px;
}

div[data-testid="stVerticalBlockBorderWrapper"] {
    background-color: #121824;
    border: 1px solid #303b50;
    border-radius: 16px;
}

div.stButton > button {
    background-color: #4f7cff;
    color: white;
    border: none;
    border-radius: 10px;
    padding: 11px 24px;
    font-weight: 600;
}

div.stButton > button:hover {
    background-color: #416be0;
    color: white;
}

div[data-baseweb="input"] input {
    color: white !important;
    background-color: #101722 !important;
}

textarea {
    color: white !important;
}

div[data-testid="stChatInput"] {
    border: 1px solid #69758b !important;
    border-radius: 14px !important;
    background-color: #121824 !important;
    box-shadow: none !important;
}

div[data-testid="stChatInput"] textarea {
    color: white !important;
}

div[data-testid="stChatInput"] button {
    background-color: white !important;
    color: #111827 !important;
    border-radius: 9px !important;
}

div[data-testid="stChatInput"] button svg {
    color: #111827 !important;
    fill: #111827 !important;
}

.section-label {
    color: #8290a8;
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 1.2px;
    font-weight: 700;
}

</style>
""", unsafe_allow_html=True)

# =====================================================
# LOGIN / SIGNUP PAGE
# =====================================================

if st.session_state.user is None:

    st.markdown(
        '<div class="main-title">⌘ CodeSnap AI</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="subtitle">'
        'Your AI-powered coding companion.'
        '</div>',
        unsafe_allow_html=True
    )

    auth_col1, auth_col2, auth_col3 = st.columns([1, 1.2, 1])

    with auth_col2:

        with st.container(border=True):

            if st.session_state.auth_page == "login":

                st.subheader("🔐 Welcome Back")

                st.write("Login to continue to CodeSnap AI.")

                email = st.text_input(
                    "Email",
                    placeholder="you@example.com",
                    key="login_email"
                )

                password = st.text_input(
                    "Password",
                    type="password",
                    key="login_password"
                )

                if st.button(
                    "Login",
                    key="login_button",
                    use_container_width=True
                ):

                    if not email or not password:
                        st.warning("Please enter your email and password.")

                    else:

                        user = authenticate_user(email, password)

                        if user:

                            st.session_state.user = user
                            st.session_state.history_loaded = False
                            st.rerun()

                        else:
                            st.error("Invalid email or password.")

                if st.button(
                    "✨ Create an account",
                    key="go_signup",
                    use_container_width=True
                ):

                    st.session_state.auth_page = "signup"
                    st.rerun()

            else:

                st.subheader("✨ Create Your Account")

                name = st.text_input(
                    "Full Name",
                    key="signup_name"
                )

                email = st.text_input(
                    "Email",
                    key="signup_email"
                )

                password = st.text_input(
                    "Password",
                    type="password",
                    key="signup_password"
                )

                confirm_password = st.text_input(
                    "Confirm Password",
                    type="password",
                    key="signup_confirm"
                )

                if st.button(
                    "Create Account",
                    key="signup_button",
                    use_container_width=True
                ):

                    if not all([name, email, password, confirm_password]):

                        st.warning("Please fill in all fields.")

                    elif password != confirm_password:

                        st.error("Passwords do not match.")

                    elif len(password) < 6:

                        st.error("Password must contain at least 6 characters.")

                    else:

                        success, user_id, message = create_user(
                            name,
                            email,
                            password
                        )

                        if success:

                            st.session_state.user = get_user(user_id)
                            st.session_state.history_loaded = False
                            st.success(message)
                            st.rerun()

                        else:
                            st.error(message)

                if st.button(
                    "Already have an account? Login",
                    key="go_login",
                    use_container_width=True
                ):

                    st.session_state.auth_page = "login"
                    st.rerun()

    st.stop()

# =====================================================
# CURRENT USER AND LOAD CHAT HISTORY
# =====================================================

user = st.session_state.user

if not st.session_state.history_loaded:

    saved_history = load_chat_history(user["id"])

    st.session_state.question_history = []

    for question, answer, created_at in saved_history:

        st.session_state.question_history.append({
            "question": question,
            "answer": answer,
            "created_at": created_at
        })

    st.session_state.history_loaded = True

# =====================================================
# SIDEBAR NAVIGATION
# =====================================================

with st.sidebar:

    st.markdown("## ⌘ CodeSnap AI")

    st.divider()

    st.markdown(
        '<div class="section-label">SIGNED IN AS</div>',
        unsafe_allow_html=True
    )

    st.markdown(f"### {user['name']}")
    st.caption(user["email"])

    st.divider()

    page = st.radio(
        "Navigation",
        [
            "🏠 Home",
            "🕘 Chat History",
            "👤 Profile",
            "⚙️ Settings"
        ],
        label_visibility="collapsed"
    )

    st.divider()

    if st.button(
        "🚪 Logout",
        key="sidebar_logout",
        use_container_width=True
    ):
        logout_user()

# =====================================================
# CHAT HISTORY PAGE
# =====================================================

if page == "🕘 Chat History":

    st.markdown(
        '<div class="section-label">YOUR CONVERSATIONS</div>',
        unsafe_allow_html=True
    )

    st.title("🕘 Chat History")

    st.write(
        "View your previous conversations with CodeSnap AI."
    )

    # Load directly from database to show saved records

    history = load_chat_history(user["id"])

    if history:

        st.caption(
            f"You have {len(history)} saved conversation(s)."
        )

        st.divider()

        # Show newest conversations first

        for index, item in enumerate(reversed(history)):

            question, answer, created_at = item

            with st.expander(
                f"💬 {question[:75]}{'...' if len(question) > 75 else ''}  |  {created_at}",
                expanded=False
            ):

                st.markdown("**You asked:**")

                st.write(question)

                st.divider()

                st.markdown("**🤖 CodeSnap AI:**")

                st.markdown(answer)

    else:

        with st.container(border=True):

            st.subheader("No conversations yet")

            st.write(
                "Your previous coding questions and AI answers "
                "will appear here."
            )

            st.info(
                "Go to Home and ask CodeSnap AI your first question."
            )

    st.stop()

# =====================================================
# PROFILE PAGE
# =====================================================

if page == "👤 Profile":

    st.markdown(
        '<div class="section-label">PROFILE</div>',
        unsafe_allow_html=True
    )

    st.title("👤 Your Profile")

    with st.container(border=True):

        st.subheader("Account Information")

        st.write("**Name:**", user["name"])
        st.write("**Email:**", user["email"])
        st.write("**Account Created:**", user["created_at"])

    if st.button("🚪 Logout", key="profile_logout"):
        logout_user()

    st.stop()

# =====================================================
# SETTINGS PAGE
# =====================================================

if page == "⚙️ Settings":

    st.markdown(
        '<div class="section-label">SETTINGS</div>',
        unsafe_allow_html=True
    )

    st.title("⚙️ Settings")

    with st.container(border=True):

        st.subheader("👤 Account")

        st.write(f"**Name:** {user['name']}")
        st.write(f"**Email:** {user['email']}")

        st.divider()

        st.subheader("🔐 Security")

        st.write(
            "Your password is stored using password hashing."
        )

        st.divider()

        st.subheader("🚪 Session")

        st.write(
            "Log out when you want to end your current session."
        )

        if st.button(
            "Logout",
            key="settings_logout",
            use_container_width=True
        ):
            logout_user()

    st.stop()

# =====================================================
# HOME PAGE
# =====================================================

st.markdown(
    '<div class="main-title">⌘ CodeSnap AI</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'Understand your code. Fix errors. Learn faster.'
    '</div>',
    unsafe_allow_html=True
)

with st.container(border=True):

    st.subheader(f"Welcome back, {user['name']} 👋")

    st.write(
        "Upload a screenshot of your code or ask a coding question. "
        "CodeSnap AI explains code, identifies errors, "
        "and suggests improvements."
    )

st.markdown('<div style="height: 30px;"></div>', unsafe_allow_html=True)

# =====================================================
# FEATURE CARDS
# =====================================================

col1, col2, col3 = st.columns(3)

with col1:
    with st.container(border=True):
        st.subheader("🔍 Explain Code")
        st.write("Understand difficult code in simple language.")

with col2:
    with st.container(border=True):
        st.subheader("🐞 Find Errors")
        st.write("Identify coding errors and understand why they occur.")

with col3:
    with st.container(border=True):
        st.subheader("✨ Suggest Fixes")
        st.write("Get corrected code and improvement suggestions.")

# =====================================================
# WORKSPACE
# =====================================================

st.divider()

st.markdown(
    '<div class="section-label">WORKSPACE</div>',
    unsafe_allow_html=True
)

st.title("💻 CodeSnap AI Workspace")

st.write(
    "Analyze code images or ask CodeSnap AI a coding question."
)

left_col, right_col = st.columns([1, 1], gap="large")

# =====================================================
# IMAGE ANALYSIS
# =====================================================

with left_col:

    with st.container(border=True):

        st.subheader("📸 Analyze Code Image")

        st.write("Upload a screenshot of your code.")

        uploaded_file = st.file_uploader(
            "Upload code screenshot",
            type=["png", "jpg", "jpeg"],
            key="code_image"
        )

        if uploaded_file:

            st.image(
                uploaded_file,
                caption="Uploaded code",
                use_container_width=True
            )

            if st.button(
                "🔍 Analyze Code",
                key="analyze_code",
                use_container_width=True
            ):

                with st.spinner("CodeSnap AI is analyzing your code..."):

                    try:

                        prompt = """
                        You are CodeSnap AI, an AI coding assistant.

                        Analyze the uploaded screenshot of code.

                        ## 1. What the Code Does
                        Explain the code in simple language.

                        ## 2. Errors Found
                        Identify visible programming errors.

                        ## 3. Why the Error Happens
                        Explain the causes.

                        ## 4. Corrected Code
                        Provide corrected code when readable.

                        ## 5. Improvements
                        Suggest ways to improve the code.

                        Do not invent unreadable code.
                        If the screenshot is unclear, mention it.
                        """

                        result = ask_gemini(prompt, uploaded_file)

                        st.session_state.image_result = result

                        save_analysis(user["id"], result)

                    except Exception as error:
                        st.error(str(error))

        if st.session_state.image_result:

            st.markdown("### 🤖 CodeSnap AI Analysis")

            with st.container(border=True):
                st.markdown(st.session_state.image_result)

            st.markdown("### 📧 Save Analysis by Email")

            analysis_email = st.text_input(
                "Email address",
                placeholder="example@gmail.com",
                key="analysis_email"
            )

            if st.button(
                "📨 Email Analysis",
                key="email_analysis",
                use_container_width=True
            ):

                if not analysis_email:
                    st.warning("Please enter an email address.")

                else:

                    with st.spinner("Sending analysis..."):

                        success, message = send_email(
                            analysis_email,
                            "CodeSnap AI - Code Analysis",
                            st.session_state.image_result
                        )

                        if success:
                            st.success(message)
                        else:
                            st.warning(message)

            st.download_button(
                "⬇️ Download Analysis",
                data=st.session_state.image_result,
                file_name="codesnap_analysis.txt",
                mime="text/plain",
                use_container_width=True
            )

# =====================================================
# CODING CHAT
# =====================================================

with right_col:

    with st.container(border=True):

        st.subheader("💬 Ask CodeSnap AI")

        st.write(
            "Ask coding questions and keep your conversations."
        )

        # Display previous conversations

        for item in st.session_state.question_history:

            with st.chat_message("user"):
                st.write(item["question"])

            with st.chat_message("assistant"):
                st.markdown(item["answer"])

        # New question

        question = st.chat_input(
            "Ask a coding question..."
        )

        if question:

            with st.chat_message("user"):
                st.write(question)

            with st.chat_message("assistant"):

                with st.spinner("CodeSnap AI is thinking..."):

                    try:

                        result = ask_gemini(
                            """
                            You are CodeSnap AI, a friendly coding
                            assistant for beginner programmers.

                            Answer the user's coding question clearly.

                            - Use simple language.
                            - Explain concepts clearly.
                            - Give examples when useful.
                            - Identify errors in provided code.
                            - Give corrected code when needed.

                            User question:

                            """ + question
                        )

                        st.markdown(result)

                        save_chat(
                            user["id"],
                            question,
                            result
                        )

                        st.session_state.question_history.append({
                            "question": question,
                            "answer": result,
                            "created_at": time.strftime(
                                "%Y-%m-%d %H:%M:%S"
                            )
                        })

                    except Exception as error:
                        st.error(str(error))

# =====================================================
# CLEAR CHAT AND ANALYSIS
# =====================================================

st.divider()

clear_col1, clear_col2, clear_col3 = st.columns([1, 1, 1])

with clear_col2:

    if st.session_state.question_history:

        if st.button(
            "🗑️ Clear All Chat History",
            key="clear_chat",
            use_container_width=True
        ):

            clear_chat_history(user["id"])

            st.session_state.question_history = []

            st.rerun()

    if st.button(
        "🔄 Clear Current Analysis",
        key="clear_analysis",
        use_container_width=True
    ):

        st.session_state.image_result = None

        st.rerun()

# =====================================================
# FOOTER
# =====================================================

st.markdown(
    """
    <div style="
        text-align: center;
        color: #657187;
        padding: 30px 0 10px 0;
        font-size: 13px;
    ">
        CodeSnap AI • AI-powered coding assistance
    </div>
    """,
    unsafe_allow_html=True
)