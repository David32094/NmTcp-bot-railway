import threading
import jwt
import random
from threading import Thread
import json
import requests
import google.protobuf
from protobuf_decoder.protobuf_decoder import Parser
import json

import datetime
from datetime import datetime
from google.protobuf.json_format import MessageToJson
import my_message_pb2
import data_pb2
import base64
import logging
import re
import socket
from google.protobuf.timestamp_pb2 import Timestamp
import jwt_generator_pb2
import os
import binascii
import sys
import psutil
import MajorLoginRes_pb2
from time import sleep
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time
import urllib3
from important_zitado import*
from byte import*

# --- START: Gemini AI Integration ---
GEMINI_API_KEY = "AIzaSyB9TsNdahfnFRhx5iX5wlTuqAaFV6uz4q8"
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"

def get_gemini_response(user_message):
    """
    Envía un mensaje a Gemini Flash 1.5 y obtiene la respuesta.
    """
    global http_session
    try:
        headers = {
            "Content-Type": "application/json"
        }
        
        payload = {
            "contents": [{
                "parts": [{
                    "text": user_message
                }]
            }]
        }
        
        url = f"{GEMINI_API_URL}?key={GEMINI_API_KEY}"
        logging.info(f"[GEMINI] Enviando solicitud a: {GEMINI_API_URL}")
        logging.info(f"[GEMINI] Payload: {json.dumps(payload, ensure_ascii=False)}")
        
        response = http_session.post(url, json=payload, headers=headers, timeout=30)
        
        logging.info(f"[GEMINI] Status Code: {response.status_code}")
        logging.info(f"[GEMINI] Response Headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            data = response.json()
            logging.info(f"[GEMINI] Response Data: {json.dumps(data, ensure_ascii=False, indent=2)}")
            
            # Extraer el texto de la respuesta
            if "candidates" in data and len(data["candidates"]) > 0:
                if "content" in data["candidates"][0] and "parts" in data["candidates"][0]["content"]:
                    if len(data["candidates"][0]["content"]["parts"]) > 0:
                        text_response = data["candidates"][0]["content"]["parts"][0].get("text", "")
                        if text_response:
                            logging.info(f"[GEMINI] Respuesta exitosa: {text_response[:100]}...")
                            return text_response
                        else:
                            logging.warning("[GEMINI] No se encontró texto en la respuesta")
                            return "Lo siento, no pude generar una respuesta."
                else:
                    logging.warning(f"[GEMINI] Estructura de respuesta inesperada: {data}")
                    return "Lo siento, no pude procesar la respuesta de la IA."
            else:
                # Verificar si hay un error en la respuesta
                if "error" in data:
                    error_msg = data["error"].get("message", "Error desconocido")
                    logging.error(f"[GEMINI] Error en respuesta: {error_msg}")
                    return f"Error de la IA: {error_msg}"
                logging.warning(f"[GEMINI] No hay candidatos en la respuesta: {data}")
                return "Lo siento, no pude procesar la respuesta de la IA."
        else:
            error_text = response.text
            logging.error(f"[GEMINI] Error HTTP {response.status_code}: {error_text}")
            try:
                error_json = response.json()
                error_msg = error_json.get("error", {}).get("message", error_text)
                logging.error(f"[GEMINI] Mensaje de error: {error_msg}")
                return f"Error de la IA: {error_msg}"
            except:
                return f"Error HTTP {response.status_code}: {error_text[:100]}"
    except requests.exceptions.Timeout:
        logging.error("[GEMINI] Timeout al conectar con la API")
        return "Lo siento, la IA tardó demasiado en responder. Intenta de nuevo."
    except requests.exceptions.RequestException as e:
        logging.error(f"[GEMINI] Error de conexión: {e}", exc_info=True)
        return "Lo siento, no pude conectarme con la IA. Intenta de nuevo más tarde."
    except Exception as e:
        logging.error(f"[GEMINI] Error inesperado: {e}", exc_info=True)
        return f"Lo siento, ocurrió un error inesperado: {str(e)[:50]}"
# --- END: Gemini AI Integration ---

# --- START: Added for improved error handling and logging ---
# Configure logging to provide clear information about the bot's status and errors.
# Configure stdout to use UTF-8 encoding for Windows compatibility
if sys.stdout.encoding != 'utf-8':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)  # Solo STDOUT para Railway
    ]
)
# --- END: Added for improved error handling and logging ---


tempid = None
sent_inv = False
start_par = False
pleaseaccept = False
nameinv = "none"
idinv = 0
senthi = False
statusinfo = False
tempdata1 = None
tempdata = None
leaveee = False
leaveee1 = False
data22 = None
isroom = False
isroom2 = False
http_session = None  # Persistent HTTP session for connection pooling
bot_start_time = time.time()  # Para calcular uptime en health check
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
def encrypt_packet(plain_text, key, iv):
    plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()
    
def gethashteam(hexxx):
    a = zitado_get_proto(hexxx)
    if not a:
        raise ValueError("Invalid hex format or empty response from zitado_get_proto")
    data = json.loads(a)
    return data['5']['7']
def getownteam(hexxx):
    a = zitado_get_proto(hexxx)
    if not a:
        raise ValueError("Invalid hex format or empty response from zitado_get_proto")
    data = json.loads(a)
    return data['5']['1']

def get_player_status(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)

    if "5" not in parsed_data or "data" not in parsed_data["5"]:
        return "OFFLINE"

    json_data = parsed_data["5"]["data"]

    if "1" not in json_data or "data" not in json_data["1"]:
        return "OFFLINE"

    data = json_data["1"]["data"]

    if "3" not in data:
        return "OFFLINE"

    status_data = data["3"]

    if "data" not in status_data:
        return "OFFLINE"

    status = status_data["data"]

    if status == 1:
        return "SOLO"
    
    if status == 2:
        if "9" in data and "data" in data["9"]:
            group_count = data["9"]["data"]
            countmax1 = data["10"]["data"]
            countmax = countmax1 + 1
            return f"INSQUAD ({group_count}/{countmax})"

        return "INSQUAD"
    
    if status in [3, 5]:
        return "INGAME"
    if status == 4:
        return "IN ROOM"
    
    if status in [6, 7]:
        return "IN SOCIAL ISLAND MODE .."

    return "NOTFOUND"
def get_idroom_by_idplayer(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)
    json_data = parsed_data["5"]["data"]
    data = json_data["1"]["data"]
    idroom = data['15']["data"]
    return idroom
def get_leader(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)
    json_data = parsed_data["5"]["data"]
    data = json_data["1"]["data"]
    leader = data['8']["data"]
    return leader
def generate_random_color():
	color_list = [
    "[00FF00][b][c]",
    "[FFDD00][b][c]",
    "[3813F3][b][c]",
    "[FF0000][b][c]",
    "[0000FF][b][c]",
    "[FFA500][b][c]",
    "[DF07F8][b][c]",
    "[11EAFD][b][c]",
    "[DCE775][b][c]",
    "[A8E6CF][b][c]",
    "[7CB342][b][c]",
    "[FF0000][b][c]",
    "[FFB300][b][c]",
    "[90EE90][b][c]"
]
	random_color = random.choice(color_list)
	return  random_color

def fix_num(num):
    fixed = ""
    count = 0
    num_str = str(num)  # Convert the number to a string

    for char in num_str:
        if char.isdigit():
            count += 1
        fixed += char
        if count == 3:
            fixed += "[c]"
            count = 0  
    return fixed


def fix_word(num):
    fixed = ""
    count = 0
    
    for char in num:
        if char:
            count += 1
        fixed += char
        if count == 3:
            fixed += "[c]"
            count = 0  
    return fixed
    
def check_banned_status(player_id):
    global http_session
    url = f"http://amin-team-api.vercel.app/check_banned?player_id={player_id}"
    try:
        response = http_session.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data  
        else:
            return {"error": f"Failed to fetch data. Status code: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}
        

# --- START: REVISED FUNCTION TO FIX THE "INVALID ID" ERROR ---
def send_vistttt(uid):
    global http_session
    try:
        # Step 1: Directly call the new visit API, removing the faulty dependency on newinfo.
        api_url = f"https://visit.vercel.app/ind/{uid}"
        response = http_session.get(api_url, timeout=15)

        # Step 2: Process the API response.
        if response.status_code == 200:
            data = response.json()
            success_count = data.get('success', 0)

            # The primary check is now the 'success' count from the visit API itself.
            if success_count > 0:
                # Extract all details from the successful response.
                nickname = data.get('nickname', 'N/A')
                level = data.get('level', 'N/A')
                likes = data.get('likes', 0)
                
                # Format a premium success message.
                return (
                    f"[b][c][00FF00]╔═ ✅ Visit Success ✅ ═╗\n\n"
                    f"[FFFFFF]Successfully sent [FFFF00]{success_count}[FFFFFF] visits to:\n\n"
                    f"[00BFFF]👤 Nickname: [FFFFFF]{nickname}\n"
                    f"[00BFFF]🆔 Player ID: [FFFFFF]{fix_num(uid)}\n"
                    f"[00BFFF]🎖️ Level: [FFFFFF]{level}\n"
                    f"[00BFFF]❤️ Likes: [FFFFFF]{fix_num(likes)}\n\n"
                    f"[00FF00]╚══════════╝"
                )
            else:
                # This handles cases where the API returns 200 but sends 0 visits,
                # which could mean the daily limit is reached or the ID is invalid.
                return (
                    f"[b][c][FF0000]╔═「 ❌ Failed ❌ 」═╗\n\n"
                    f"[FFFFFF]Could not send visits to ID: [FFFF00]{fix_num(uid)}\n"
                    f"[FFFFFF]The ID may be invalid or the daily\n"
                    f"[FFFFFF]visit limit has been reached.\n\n"
                    f"[FF0000]╚══════════╝"
                )
        else:
            # Handle API server errors (like 402, 404, 500). This now serves
            # as the primary "Invalid ID" check.
            return (
                f"[b][c][FF0000]╔═「 ❌ Error ❌ 」═╗\n\n"
                f"[FFFFFF]Invalid Player ID or API Error.\n"
                f"[FFFFFF]Server returned status: [FFFF00]{response.status_code}\n\n"
                f"[FF0000]╚══════════╝"
            )

    except requests.exceptions.RequestException:
        # Handle network or connection errors.
        return (
            f"[b][c][FF0000]╔═「 🔌 Connection Error 🔌 」═╗\n\n"
            f"[FFFFFF]Could not connect to the visit API server.\n"
            f"[FFFFFF]Please try again later.\n\n"
            f"[FF0000]╚══════════╝"
        )
    except Exception as e:
        # Handle any other unexpected errors.
        logging.error(f"An unexpected error occurred in send_vistttt: {str(e)}")
        return (
            f"[b][c][FF0000]╔═「 ⚙️ System Error ⚙️ 」═╗\n\n"
            f"[FFFFFF]An unexpected error occurred.\n"
            f"[FFFFFF]Check the logs for more details.\n\n"
            f"[FF0000]╚══════════╝"
        )
# --- END: REVISED FUNCTION ---


def rrrrrrrrrrrrrr(number):
    if isinstance(number, str) and '***' in number:
        return number.replace('***', '106')
    return number
def newinfo(uid):
    global http_session
    try:
        # The new API URL
        url = f"https://jnl-tcp-info.vercel.app/player-info?uid={uid}"
        # Make the request with a timeout to prevent it from hanging
        response = http_session.get(url, timeout=15)

        # A successful request returns status code 200
        if response.status_code == 200:
            data = response.json()
            # Check for a key like 'AccountName' to confirm the API returned valid data
            if "AccountName" in data and data["AccountName"]:
                return {"status": "ok", "info": data}
            else:
                # This handles cases where the API returns 200 but the ID was invalid
                return {"status": "wrong_id"}
        else:
            logging.error(f"Error: API returned status code {response.status_code} for UID {uid}")
            return {"status": "wrong_id"}

    except requests.exceptions.RequestException as e:
        # Handle network issues like timeouts or connection errors
        logging.error(f"Error during newinfo request: {str(e)}")
        return {"status": "error", "message": str(e)}
    except Exception as e:
        # Handle any other unexpected errors
        logging.error(f"An unexpected error occurred in newinfo: {str(e)}")
        return {"status": "error", "message": str(e)}
	
import requests

# --- START: CORRECTED SPAM FUNCTION TO FIX "ERROR IN ID" ---
def send_spam(uid):
    global http_session
    try:
        # Step 1: Directly call the new spam API. The faulty newinfo() check has been removed.
        api_url = f"https://spam.vercel.app/send_requests?uid={uid}"
        response = http_session.get(api_url, timeout=15)

        # Step 2: Process the detailed API response.
        if response.status_code == 200:
            data = response.json()
            success_count = data.get('success_count', 0)
            failed_count = data.get('failed_count', 0)

            # Check if the API managed to send any requests successfully.
            if success_count > 0:
                # Format a detailed success message.
                return (
                    f"[b][c][00FF00]╔═══ ✅ Spam Success ✅ ═══╗\n\n"
                    f"[FFFFFF]Friend requests sent to:\n"
                    f"[00BFFF]🆔 Player ID: [FFFFFF]{fix_num(uid)}\n\n"
                    f"[00FF00]✓ Success: [FFFFFF]{success_count}\n"
                    f"[FF0000]✗ Failed:  [FFFFFF]{failed_count}\n\n"
                    f"[00FF00]╚══════════════════════╝"
                )
            else:
                # Handle cases where the API call worked but no requests were sent.
                # This could mean the ID is invalid or a server limit was hit.
                return (
                    f"[b][c][FF0000]╔═══════「 ⚠️ Failed ⚠️ 」═══════╗\n\n"
                    f"[FFFFFF]Could not send requests to ID:\n"
                    f"[FFFF00]{fix_num(uid)}\n\n"
                    f"[FFFFFF]The ID may be invalid or the\n"
                    f"[FFFFFF]server has reached its limit.\n"
                    f"[FF0000]╚═══════════════════════════╝"
                )
        else:
            # Handle API server errors (e.g., 404, 500).
            return (
                f"[b][c][FF0000]╔═══════「 ❌ API Error ❌ 」═══════╗\n\n"
                f"[FFFFFF]The spam server returned an error.\n"
                f"[FFFFFF]Status Code: [FFFF00]{response.status_code}\n\n"
                f"[FF0000]╚════════════════════════════╝"
            )

    except requests.exceptions.RequestException:
        # Handle network or connection errors.
        return (
            f"[b][c][FF0000]╔════「 🔌 Connection Error 🔌 」════╗\n\n"
            f"[FFFFFF]Could not connect to the spam API server.\n"
            f"[FFFFFF]Please try again later.\n\n"
            f"[FF0000]╚══════════════════════════════╝"
        )
    except Exception as e:
        # Handle any other unexpected errors.
        logging.error(f"An unexpected error occurred in send_spam: {str(e)}")
        return (
            f"[b][c][FF0000]╔════「 ⚙️ System Error ⚙️ 」════╗\n\n"
            f"[FFFFFF]An unexpected error occurred.\n"
            f"[FFFFFF]Check the logs for more details.\n\n"
            f"[FF0000]╚══════════════════════════╝"
        )
# --- END: CORRECTED SPAM FUNCTION ---
def attack_profail(player_id):
    global http_session
    url = f"https://visit-taupe.vercel.app/visit/{player_id}"
    res = http_session.get(url, timeout=10)
    if res.status_code == 200:
        logging.info("Done-Attack")
    else:
        logging.error("Fuck-Attack")

def send_likes(uid):
    global http_session
    try:
        # The new API URL with the provided key
        api_url = f"https://ron.vercel.app/like?uid={uid}&server_name=ind&key=W8IDwCgQbMXYyxNUCmPhcBb3tW56ys3Y"
        
        # Make the request with a timeout to prevent it from hanging
        likes_api_response = http_session.get(api_url, timeout=15)
        
        # Check if the API request was successful (HTTP 200 OK)
        if likes_api_response.status_code == 200:
            api_json_response = likes_api_response.json()
            
            # The actual data is inside the "response" object
            response_data = api_json_response.get('response', {})
            
            # Extract all relevant fields from the API response
            likes_added = response_data.get('LikesGivenByAPI', 0)
            player_name = response_data.get('PlayerNickname', 'N/A')
            likes_before = response_data.get('LikesbeforeCommand', 0)
            likes_after = response_data.get('LikesafterCommand', 0)
            key_remaining = response_data.get('KeyRemainingRequests', 'N/A')

            # This is the success case, where LikesGivenByAPI is greater than 0
            if likes_added > 0:
                return {
                    "status": "ok",
                    "message": (
                        f"[C][B][00FF00]________________________\n"
                        f" ✅ Likes Sent Successfully!\n\n"
                        f" 👤 Name: {player_name}\n"
                        f" 🌏 Region: IND\n"
                        f" 👍 Likes Given: [FFFF00]{likes_added}\n"  # This line shows the total likes sent
                        f" ❤️ Before: {likes_before} ➔ After: {likes_after}\n\n"
                        f" 🔑 Key Remaining: [00FFFF]{key_remaining}\n"
                        f"________________________"
                    )
                }
            else:
                # This is the case where the daily limit for that specific UID has been reached
                return {
                    "status": "failed",
                    "message": (
                        f"[C][B][FF0000]________________________\n"
                        f" ❌ Daily like limit reached for this UID.\n"
                        f" Please try again after 4 AM IST or use a different UID.\n\n"
                        f" 🔑 Key Remaining: [00FFFF]{key_remaining}\n"
                        f"________________________"
                    )
                }
        else:
            # This handles API server errors (e.g., 404 Not Found, 500 Internal Server Error)
            return {
                "status": "failed",
                "message": (
                    f"[C][B][FF0000]________________________\n"
                    f" ❌ API Error!\n"
                    f" Status Code: {likes_api_response.status_code}\n"
                    f" Please check the UID and try again.\n"
                    f"________________________"
                )
            }

    except requests.exceptions.RequestException:
        # This handles network errors (e.g., timeout, no connection)
        return {
            "status": "failed",
            "message": (
                f"[C][B][FF0000]________________________\n"
                f" ❌ API Connection Failed!\n"
                f" The like server may be down. Please try again later.\n"
                f"________________________"
            )
        }
    except Exception as e:
        # This catches any other unexpected errors
        return {
            "status": "failed",
            "message": (
                f"[C][B][FF0000]________________________\n"
                f" ❌ An unexpected error occurred: {str(e)}\n"
                f"________________________"
            )
        }

def get_info(uid):
    global http_session
    try:
        # Attempt to connect to the player info API
        info_api_response = http_session.get(
            f"https://jnl-tcp-info.vercel.app/player-info?uid={uid}",
            timeout=15  # Add a timeout to prevent it from hanging
        )
        
        # Check if the API request was successful
        if info_api_response.status_code == 200:
            api_json_response = info_api_response.json()
            
            # Extract relevant fields from the response
            account_name = api_json_response.get('AccountName', 'Unknown')
            account_level = api_json_response.get('AccountLevel', 0)
            account_likes = api_json_response.get('AccountLikes', 0)
            account_region = api_json_response.get('AccountRegion', 'Unknown')
            br_max_rank = api_json_response.get('BrMaxRank', 0)
            cs_max_rank = api_json_response.get('CsMaxRank', 0)
            guild_name = api_json_response.get('GuildName', 'None')
            signature = api_json_response.get('signature', 'No signature')

            # Case: Success with player details
            return {
                "status": "ok",
                "message": (
                    f"[C][B][00FF00]________________________\n"
                    f" ✅ Player Information\n"
                    f" Name: {account_name}\n"
                    f" Level: {account_level}\n"
                    f" Likes: {account_likes}\n"
                    f" Region: {account_region}\n"
                    f" BR Max Rank: {br_max_rank}\n"
                    f" CS Max Rank: {cs_max_rank}\n"
                    f" Guild: {guild_name}\n"
                    f" Signature: {signature}\n"
                    f"________________________"
                )
            }
        else:
            # Case: General API failure
            return {
                "status": "failed",
                "message": (
                    f"[C][B][FF0000]________________________\n"
                    f" ❌ Failed to fetch player info!\n"
                    f" Please check the validity of the User ID\n"
                    f"________________________"
                )
            }

    except requests.exceptions.RequestException:
        # Handle network errors (e.g., API is not running)
        return {
            "status": "failed",
            "message": (
                f"[C][B][FF0000]________________________\n"
                f" ❌ API Connection Failed!\n"
                f" Please ensure the API server is running\n"
                f"________________________"
            )
        }
    except Exception as e:
        # Catch any other unexpected errors
        return {
            "status": "failed",
            "message": (
                f"[C][B][FF0000]________________________\n"
                f" ❌ An unexpected error occurred: {str(e)}\n"
                f"________________________"
            )
        }        
		
def Encrypt(number):
    number = int(number)  # Convert the number to an integer
    encoded_bytes = []    # Create a list to store the encoded bytes

    while True:  # Loop that continues until the number is fully encoded
        byte = number & 0x7F  # Extract the least 7 bits of the number
        number >>= 7  # Shift the number to the right by 7 bits
        if number:
            byte |= 0x80  # Set the eighth bit to 1 if the number still contains additional bits

        encoded_bytes.append(byte)
        if not number:
            break  # Stop if no additional bits are left in the number

    return bytes(encoded_bytes).hex()
    


def get_random_avatar():
	avatar_list = [
         '902050001', '902050002', '902050003', '902039016', '902050004', 
        '902047011', '902047010', '902049015', '902050006', '902049020'
    ]
	random_avatar = random.choice(avatar_list)
	return  random_avatar

class FF_CLIENT(threading.Thread):
    def __init__(self, id, password):
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        self.get_tok()
    def connect(self, tok, host, port, packet, key, iv):
        global clients
        clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = int(port)
        clients.connect((host, port))
        clients.send(bytes.fromhex(tok))

        while True:
            data = clients.recv(9999)
            if data == b"":
                logging.error("Connection closed by remote host")
                break
def get_available_room(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_objects = parsed_results
        parsed_results_dict = parse_results(parsed_results_objects)
        json_data = json.dumps(parsed_results_dict)
        return json_data
    except Exception as e:
        logging.error(f"error {e}")
        return None

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data["wire_type"] = result.wire_type
        if result.wire_type == "varint":
            field_data["data"] = result.data
        if result.wire_type == "string":
            field_data["data"] = result.data
        if result.wire_type == "bytes":
            field_data["data"] = result.data
        elif result.wire_type == "length_delimited":
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict

def dec_to_hex(ask):
    ask_result = hex(ask)
    final_result = str(ask_result)[2:]
    if len(final_result) == 1:
        final_result = "0" + final_result
    return final_result

def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return binascii.hexlify(encrypted_message).decode('utf-8')

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def extract_jwt_from_hex(hex):
    byte_data = binascii.unhexlify(hex)
    message = jwt_generator_pb2.Garena_420()
    message.ParseFromString(byte_data)
    json_output = MessageToJson(message)
    token_data = json.loads(json_output)
    return token_data
    

def format_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

# --- START: Modified for improved error handling ---
# This function is now the single point for safely restarting the script.
def restart_program():
    logging.warning("Initiating bot restart...")
    
    # Limpiar el lock file antes de reiniciar
    lock_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.bot_lock')
    try:
        if os.path.exists(lock_file):
            os.remove(lock_file)
    except Exception as e:
        logging.warning(f"Error eliminando lock file: {e}")
    
    # Esperar un poco antes de reiniciar para evitar bucles infinitos
    logging.info("Esperando 3 segundos antes de reiniciar...")
    time.sleep(3)
    
    # Intentar cerrar conexiones HTTP de forma segura
    try:
        global http_session
        if http_session:
            try:
                http_session.close()
            except:
                pass
    except:
        pass
    
    # NO intentar cerrar descriptores de archivo manualmente - causa errores OSError
    # Python y el sistema operativo los cerrarán automáticamente al terminar el proceso
    
    # Replace the current process with a new instance of the script
    try:
        python = sys.executable
        script_path = os.path.abspath(__file__)
        # Use subprocess for more reliable restart
        import subprocess
        subprocess.Popen([python, script_path], cwd=os.path.dirname(script_path))
        sys.exit(0)
    except Exception as e:
        logging.critical(f"Failed to restart program: {e}")
        # Fallback: try os.execl
        try:
            python = sys.executable
            os.execl(python, python, *sys.argv)
        except Exception as e2:
            logging.critical(f"Fallback restart also failed: {e2}")
            sys.exit(1)
# --- END: Modified for improved error handling ---
          
class FF_CLIENT(threading.Thread):
    def __init__(self, id, password):
        super().__init__()
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        # --- START: Added for periodic restart ---
        # Record the start time to track uptime.
        self.start_time = time.time()
        # --- END: Added for periodic restart ---
        self.get_tok()

    def parse_my_message(self, serialized_data):
        try:
            MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
            MajorLogRes.ParseFromString(serialized_data)
            key = MajorLogRes.ak
            iv = MajorLogRes.aiv
            if isinstance(key, bytes):
                key = key.hex()
            if isinstance(iv, bytes):
                iv = iv.hex()
            self.key = key
            self.iv = iv
            logging.info(f"Key: {self.key} | IV: {self.iv}")
            return self.key, self.iv
        except Exception as e:
            logging.error(f"{e}")
            return None, None

    def nmnmmmmn(self, data):
        key, iv = self.key, self.iv
        try:
            key = key if isinstance(key, bytes) else bytes.fromhex(key)
            iv = iv if isinstance(iv, bytes) else bytes.fromhex(iv)
            data = bytes.fromhex(data)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            cipher_text = cipher.encrypt(pad(data, AES.block_size))
            return cipher_text.hex()
        except Exception as e:
            logging.error(f"Error in nmnmmmmn: {e}")

    
    def send_emote(self, target_id, emote_id):
        """
        Creates and prepares the packet for sending an emote to a target player.
        """
        fields = {
            1: 21,
            2: {
                1: 804266360,  # Constant value from original code
                2: 909000001,  # Constant value from original code
                5: {
                    1: int(target_id),
                    3: int(emote_id),
                }
            }
        }
        packet = create_protobuf_packet(fields).hex()
        # The packet type '0515' is used for online/squad actions
        header_lenth = len(encrypt_packet(packet, self.key, self.iv)) // 2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        else:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)    

    def NoTmeowl(self, client_id):
        key, iv = self.key, self.iv
        banner_text = f"""
everything ok
        """        
        fields = {
            1: 5,
            2: {
                1: int(client_id),
                2: 1,
                3: int(client_id),
                4: banner_text
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final +  self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)    

    def NoTmeowl1(self, client_id):
        key, iv = self.key, self.iv
        gay_text = f"""
[0000FF]Done        
         """        
        fields = {
            1: int(client_id),
            2: 5,
            4: 50,
            5: {
                1: int(client_id),
                2: gay_text,
                3: 1
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final +  self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    
    
    def spam_room(self, idroom, idplayer):
        fields = {
        1: 78,
        2: {
            1: int(idroom),
            2: "iG:[C][B][FF0000] NoTmeowl",
            4: 330,
            5: 6000,
            6: 201,
            10: int(get_random_avatar()),
            11: int(idplayer),
            12: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def send_squad(self, idplayer):
        fields = {
            1: 33,
            2: {
                1: int(idplayer),
                2: "IND",
                3: 1,
                4: 1,
                7: 330,
                8: 19459,
                9: 100,
                12: 1,
                16: 1,
                17: {
                2: 94,
                6: 11,
                8: "1.109.5",
                9: 3,
                10: 2
                },
                18: 201,
                23: {
                2: 1,
                3: 1
                },
                24: int(get_random_avatar()),
                26: {},
                28: {}
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def start_autooo(self):
        fields = {
        1: 9,
        2: {
            1: 12480598706
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def invite_skwad(self, idplayer):
        fields = {
        1: 2,
        2: {
            1: int(idplayer),
            2: "IND",
            4: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def request_join_squad(self, idplayer):
        import random
        same_value = random.choice([4096, 16384, 8192])
        fields = {
        1: 33,
        2: {
            1: int(idplayer),
            2: "IND",
            3: 1,
            4: 1,
            5: bytes([1, 7, 9, 10, 11, 18, 25, 26, 32]),
            6: "iG:[C][B][FF0000] NoTmeowl",
            7: 330,
            8: 1000,
            10: "IND",
            11: bytes([49, 97, 99, 52, 98, 56, 48, 101, 99, 102, 48, 52, 55, 56,
            97, 52, 52, 50, 48, 51, 98, 102, 56, 102, 97, 99, 54, 49, 50, 48, 102, 53]),
            12: 1,
            13: int(idplayer),
            14: {
            1: 2203434355,
            2: 8,
            3: "\u0010\u0015\b\n\u000b\u0013\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"
            },
            16: 1,
            17: 1,
            18: 312,
            19: 46,
            23: bytes([16, 1, 24, 1]),
            24: int(get_random_avatar()),
            26: "",
            28: "",
            31: {
            1: 1,
            2: same_value
            },
            32: same_value,
            34: {
            1: int(idplayer),
            2: 8,
            3: bytes([15,6,21,8,10,11,19,12,17,4,14,20,7,2,1,5,16,3,13,18])
            }
        },
        10: "en",
        13: {
            2: 1,
            3: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def request_join_fffffsquad(self, idplayer):
        fields = {
        1: 33,
        2: {
            1: int(idplayer),
            2: "IND",
            3: 1,
            4: 1,
            7: 330,
            8: 19459,
            9: 100,
            12: 1,
            16: 1,
            17: {
            2: 94,
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
            18: 201,
            23: {
            2: 1,
            3: 1
            },
            24: int(get_random_avatar()),
            26: {},
            28: {}
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def skwad_maker(self):
        fields = {
        1: 1,
        2: {
            2: "\u0001",
            3: 1,
            4: 1,
            5: "en",
            9: 1,
            11: 1,
            13: 1,
            14: {
            2: 5756,
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def changes(self, num):
        fields = {
        1: 17,
        2: {
            1: 12480598706,
            2: 1,
            3: int(num),
            4: 60,
            5: "\u001a",
            8: 5,
            13: 329
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
   
    def leave_s(self):
        fields = {
        1: 7,
        2: {
            1: 12480598706
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def leave_room(self, idroom):
        fields = {
        1: 6,
        2: {
            1: int(idroom)
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def stauts_infoo(self, idd):
        fields = {
        1: 7,
        2: {
            1: 12480598706
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
        #logging.info(Besto_Packet)
    def GenResponsMsg(self, Msg, Enc_Id):
        # Log cuando se genera un mensaje de respuesta
        logging.info(f"[ENVIANDO MENSAJE] Para UID: {Enc_Id} | Mensaje: {Msg[:100]}...")
        
        fields = {
            1: 1,
            2: {
                1: 12947146032,
                2: Enc_Id,
                3: 2,
                4: str(Msg),
                5: int(datetime.now().timestamp()),
                7: 2,
                9: {
                    1: "NoTmeowl",
                    2: int(get_random_avatar()),
                    3: 901049014,
                    4: 330,
                    5: 801040108,
                    8: "Friend",
                    10: 1,
                    11: 1,
                    13: {
                        1: 2,
                        2: 1,
                    },
                    14: {
                        1: 11017917409,
                        2: 8,
                        3: "\u0010\u0015\b\n\u000b\u0013\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"
                    }
                },
                10: "IND",
                13: {
                    1: "https://graph.facebook.com/v9.0/253082355523299/picture?width=160&height=160",
                    2: 1,
                    3: 1
                },
                14: {
                    1: {
                        1: random.choice([1, 4]),
                        2: 1,
                        3: random.randint(1, 180),
                        4: 1,
                        5: int(datetime.now().timestamp()),
                        6: "IND"
                    }
                }
            }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "1215000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "121500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "12150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "1215000" + header_lenth_final + self.nmnmmmmn(packet)
        
        result = bytes.fromhex(final_packet)
        logging.info(f"[OK] MENSAJE GENERADO - Tamaño del paquete: {len(result)} bytes | UID destino: {Enc_Id}")
        return result
    def createpacketinfo(self, idddd):
        ida = Encrypt(idddd)
        packet = f"080112090A05{ida}1005"
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0F15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0F1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0F150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0F15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def accept_sq(self, hashteam, idplayer, ownerr):
        fields = {
        1: 4,
        2: {
            1: int(ownerr),
            3: int(idplayer),
            4: "\u0001\u0007\t\n\u0012\u0019\u001a ",
            8: 1,
            9: {
            2: 1393,
            4: "AlwaysJexarHere",
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
            10: hashteam,
            12: 1,
            13: "en",
            16: "OR"
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def info_room(self, idrooom):
        fields = {
        1: 1,
        2: {
            1: int(idrooom),
            3: {},
            4: 1,
            6: "en"
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def sockf1(self, tok, online_ip, online_port, packet, key, iv):
        global socket_client
        global sent_inv
        global tempid
        global start_par
        global clients
        global pleaseaccept
        global tempdata1
        global nameinv
        global idinv
        global senthi
        global statusinfo
        global tempdata
        global data22
        global leaveee
        global isroom
        global isroom2
        socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        online_port = int(online_port)

        socket_client.connect((online_ip,online_port))
        logging.info(f" Con port {online_port} Host {online_ip} ")
        #logging.info(tok)
        socket_client.send(bytes.fromhex(tok))
        
        # Establecer este cliente como activo para el panel cuando el socket esté conectado
        global active_client_instance
        if active_client_instance is None or not hasattr(active_client_instance, 'id') or active_client_instance.id != self.id:
            set_active_client(self)
            logging.info(f"[PANEL] Cliente {self.id} establecido como activo después de conectar socket")
        while True:
            try:
                # --- START: Added for periodic restart ---
                # Deshabilitado en Railway - causa problemas con reinicios frecuentes
                # En Railway, el servicio debe mantenerse activo sin reinicios programados
                RESTART_INTERVAL = int(os.environ.get('RESTART_INTERVAL', 86400))  # Default: 24 horas (86400 segundos)
                if RESTART_INTERVAL > 0 and time.time() - self.start_time > RESTART_INTERVAL:
                    logging.warning(f"Scheduled restart after {RESTART_INTERVAL} seconds from sockf1.")
                    restart_program()
                # --- END: Added for periodic restart ---

                data2 = socket_client.recv(9999)
                #logging.info(data2)
                if "0500" in data2.hex()[0:4]:
                    accept_packet = f'08{data2.hex().split("08", 1)[1]}'
                    kk = get_available_room(accept_packet)
                    parsed_data = json.loads(kk)
                    fark = parsed_data.get("4", {}).get("data", None)
                    if fark is not None:
                        #logging.info(f"haaaaaaaaaaaaaaaaaaaaaaho {fark}")
                        if fark == 18:
                            if sent_inv:
                                accept_packet = f'08{data2.hex().split("08", 1)[1]}'
                                #logging.info(accept_packet)
                                #logging.info(tempid)
                                aa = gethashteam(accept_packet)
                                ownerid = getownteam(accept_packet)
                                #logging.info(ownerid)
                                #logging.info(aa)
                                ss = self.accept_sq(aa, tempid, int(ownerid))
                                socket_client.send(ss)
                                sleep(1)
                                startauto = self.start_autooo()
                                socket_client.send(startauto)
                                start_par = False
                                sent_inv = False
                        if fark == 6:
                            leaveee = True
                            logging.info("kaynaaaaaaaaaaaaaaaa")
                        if fark == 50:
                            pleaseaccept = True
                    #logging.info(data2.hex())

                if "0600" in data2.hex()[0:4] and len(data2.hex()) > 700:
                        accept_packet = f'08{data2.hex().split("08", 1)[1]}'
                        kk = get_available_room(accept_packet)
                        parsed_data = json.loads(kk)
                        #logging.info(parsed_data)
                        idinv = parsed_data["5"]["data"]["1"]["data"]
                        nameinv = parsed_data["5"]["data"]["3"]["data"]
                        senthi = True
                if "0f00" in data2.hex()[0:4]:
                    packett = f'08{data2.hex().split("08", 1)[1]}'
                    #logging.info(packett)
                    kk = get_available_room(packett)
                    parsed_data = json.loads(kk)
                    
                    asdj = parsed_data["2"]["data"]
                    tempdata = get_player_status(packett)
                    if asdj == 15:
                        if tempdata == "OFFLINE":
                            tempdata = f"The id is {tempdata}"
                        else:
                            idplayer = parsed_data["5"]["data"]["1"]["data"]["1"]["data"]
                            idplayer1 = fix_num(idplayer)
                            if tempdata == "IN ROOM":
                                idrooom = get_idroom_by_idplayer(packett)
                                idrooom1 = fix_num(idrooom)
                                
                                tempdata = f"id : {idplayer1}\nstatus : {tempdata}\nid room : {idrooom1}"
                                data22 = packett
                                #logging.info(data22)
                                
                            if "INSQUAD" in tempdata:
                                idleader = get_leader(packett)
                                idleader1 = fix_num(idleader)
                                tempdata = f"id : {idplayer1}\nstatus : {tempdata}\nleader id : {idleader1}"
                            else:
                                tempdata = f"id : {idplayer1}\nstatus : {tempdata}"
                        statusinfo = True 

                        #logging.info(data2.hex())
                        #logging.info(tempdata)
                    
                        

                    else:
                        pass
                if "0e00" in data2.hex()[0:4]:
                    packett = f'08{data2.hex().split("08", 1)[1]}'
                    #logging.info(packett)
                    kk = get_available_room(packett)
                    parsed_data = json.loads(kk)
                    idplayer1 = fix_num(idplayer)
                    asdj = parsed_data["2"]["data"]
                    tempdata1 = get_player_status(packett)
                    if asdj == 14:
                        nameroom = parsed_data["5"]["data"]["1"]["data"]["2"]["data"]
                        
                        maxplayer = parsed_data["5"]["data"]["1"]["data"]["7"]["data"]
                        maxplayer1 = fix_num(maxplayer)
                        nowplayer = parsed_data["5"]["data"]["1"]["data"]["6"]["data"]
                        nowplayer1 = fix_num(nowplayer)
                        tempdata1 = f"{tempdata}\nRoom name : {nameroom}\nMax player : {maxplayer1}\nLive player : {nowplayer1}"
                        #logging.info(tempdata1)
                        

                        
                    
                        
                if data2 == b"":
                    
                    logging.error("Connection closed by remote host in sockf1. Restarting.")
                    restart_program()
                    break
            except Exception as e:
                logging.critical(f"Unhandled error in sockf1 loop: {e}. Restarting bot.")
                restart_program()
    
    
    def connect(self, tok, packet, key, iv, whisper_ip, whisper_port, online_ip, online_port):
        global clients
        global socket_client
        global sent_inv
        global tempid
        global leaveee
        global start_par
        global nameinv
        global idinv
        global senthi
        global statusinfo
        global tempdata
        global pleaseaccept
        global tempdata1
        global data22
        clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clients.connect((whisper_ip, whisper_port))
        clients.send(bytes.fromhex(tok))
        
        # Establecer este cliente como activo para el panel cuando se conecte
        global active_client_instance
        set_active_client(self)
        logging.info(f"[PANEL] Cliente {self.id} establecido como activo después de conectar whisper")
        
        thread = threading.Thread(
            target=self.sockf1, args=(tok, online_ip, online_port, "anything", key, iv)
        )
        threads.append(thread)
        thread.start()

        while True:
            # --- START: Added for periodic restart and error handling ---
            # Deshabilitado en Railway - causa problemas con reinicios frecuentes
            # En Railway, el servicio debe mantenerse activo sin reinicios programados
            RESTART_INTERVAL = int(os.environ.get('RESTART_INTERVAL', 86400))  # Default: 24 horas (86400 segundos)
            if RESTART_INTERVAL > 0 and time.time() - self.start_time > RESTART_INTERVAL:
                logging.warning(f"Scheduled restart after {RESTART_INTERVAL} seconds from connect loop.")
                restart_program()
            
            try:
            # --- END: Added for periodic restart and error handling ---
                data = clients.recv(9999)

                if data == b"":
                    logging.error("Connection closed by remote host in connect loop. Restarting.")
                    restart_program()
                    break
                #logging.info(f"Received data: {data}")
                
                if senthi == True:
                    
                    clients.send(
                            self.GenResponsMsg(
                                f"""[C][B][FF1493]╔══════════════════════════╗
[FFFFFF]✨ Hello!  
[FFFFFF]❤️ Thank you for adding me!  
[FFFFFF]⚡ To see my commands:  
[FFFFFF]👉 Send /help or any emoji  
[FF1493]╠══════════════════════════╣
[FFFFFF]🤖 Want to buy a bot?  
[FFFFFF]📩 Contact the developer  
[FFD700]👑 NAME : [FFFF00]NoTmeowl
[FFD700]📌 INSTAGRAM : [00BFFF]@krishná.códer  
[FF1493]╚══════════════════════════╝""", idinv
                            )
                    )
                    senthi = False
#-------------------------------------------------------------#                
                if "1200" in data.hex()[0:4]:
                    logging.info(f"[RECIBIDO] MENSAJE - Codigo: 1200 | Tamano: {len(data)} bytes")
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    
                    # DEBUG: Mostrar estructura completa del mensaje
                    logging.info(f"[DEBUG] Estructura completa del mensaje: {json.dumps(parsed_data, indent=2, ensure_ascii=False)}")
                    
                    try:
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        logging.info(f"[USUARIO] UID del remitente: {uid}")
                    except KeyError:
                        logging.warning("Warning: '1' key is missing in parsed_data, skipping...")
                        uid = None  # Set a default value
                    
                    # Buscar el mensaje de texto en diferentes ubicaciones posibles
                    message_text = None
                    message_lower = None
                    
                    # Método 1: Campo "8" tradicional
                    if "8" in parsed_data["5"]["data"] and "data" in parsed_data["5"]["data"]["8"]:
                        message_text = parsed_data["5"]["data"]["8"]["data"]
                        logging.info(f"[DEBUG] Mensaje encontrado en campo '8': '{message_text}'")
                    # Método 2: Buscar en otros campos
                    elif "4" in parsed_data["5"]["data"] and "data" in parsed_data["5"]["data"]["4"]:
                        message_text = parsed_data["5"]["data"]["4"]["data"]
                        logging.info(f"[DEBUG] Mensaje encontrado en campo '4': '{message_text}'")
                    # Método 3: Buscar directamente en los datos
                    elif "data" in parsed_data["5"]["data"]:
                        for key, value in parsed_data["5"]["data"].items():
                            if isinstance(value, dict) and "data" in value:
                                potential_text = value["data"]
                                if isinstance(potential_text, str) and len(potential_text) < 200:
                                    logging.info(f"[DEBUG] Campo '{key}' contiene texto: '{potential_text}'")
                                    if not message_text:  # Usar el primero que encontremos
                                        message_text = potential_text
                    
                    if message_text:
                        if message_text == "DefaultMessageWithKey":
                            logging.info("[INFO] MENSAJE - Tipo: DefaultMessageWithKey (ignorado)")
                            pass
                        else:
                            message_lower = message_text.lower().strip()
                            logging.info(f"[MENSAJE DE TEXTO] Original: '{message_text}' | Normalizado: '{message_lower}' | UID: {uid}")
                            
                            # Verificar si es un comando (empieza con /)
                            if message_lower.startswith('/'):
                                logging.info(f"[COMANDO] Comando detectado (ignorado por IA): '{message_lower}'")
                            else:
                                # Si NO es un comando, enviar a Gemini AI
                                logging.info(f"[IA] Mensaje recibido de UID {uid}: '{message_text}' - Enviando a Gemini...")
                                
                                # Obtener respuesta de Gemini
                                ai_response = get_gemini_response(message_text)
                                
                                # Enviar respuesta de la IA al usuario
                                response_msg = self.GenResponsMsg(
                                    f"[C][B][00BFFF]{ai_response}", uid
                                )
                                clients.send(response_msg)
                                logging.info(f"[IA] Respuesta enviada a UID {uid}: '{ai_response[:50]}...'")
                    else:
                        logging.info("[INFO] MENSAJE - No se encontro texto del mensaje en ningun campo conocido")
                        logging.info(f"[DEBUG] Campos disponibles en parsed_data['5']['data']: {list(parsed_data.get('5', {}).get('data', {}).keys())}")
                        pass  
#-------------------------------------------------------------#
                if "1200" in data.hex()[0:4] and b"/admin" in data:
                    try:
                        logging.info(f"[COMANDO RECIBIDO] /admin detectado")
                        i = re.split("/admin", str(data))[1]
                        if "***" in i:
                            i = i.replace("***", "106")
                        sid = str(i).split("(\\x")[0]
                        logging.info(f"[PARAMETROS] /admin con SID: {sid}")
                        json_result = get_available_room(data.hex()[10:])
                        
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        logging.info(f"[USUARIO] UID del remitente: {uid}")
                        logging.info(f"[ENVIANDO] Respuesta de /admin a UID: {uid}")
                        admin_response = self.GenResponsMsg(
                            f"""[C][B][FF0000]╔══════════╗
[FFFFFF]✨ If anyone wants to buy TCP bot  
[FFFFFF]          ⚡ Or purchase access ❤️  
[FFFFFF]                   Just contact me...  
[FF0000]╠══════════╣
[FFD700]⚡ OWNER : [FFFFFF]NoTmeowl
[FFD700]⚡ INSTAGRAM : [FFFFFF]@krishná.códer
[FFD700]✨ Name on Telegram : [FFFFFF] teamxNoTmeowl
[FF0000]╚══════════╝
[FFD700]✨ Developer —͟͞͞ </> NoTmeowl ⚡""", uid
                        )
                        clients.send(admin_response)
                        logging.info(f"[OK] ENVIADO - Respuesta de /admin enviada exitosamente a UID: {uid}")
                    except Exception as e:
                        logging.error(f"[ERROR] Error processing /admin command: {e}. Restarting.")
                        restart_program()                
#-------------------------------------------------------------#
                if "1200" in data.hex()[0:4] and b"/sm" in data:
                    try:
                        # Get the UID of the user who sent the command to send a reply
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]

                        # Improved Parsing: Use a regular expression to find the ID more reliably
                        match = re.search(r'/sm\s*(\d+)', str(data))
                        
                        if match:
                            player_id_str = match.group(1)

                            # Send an initial confirmation message
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][1E90FF]Request received! Preparing to spam {fix_num(player_id_str)}...", uid
                                )
                            )

                            # --- START OF THE FIX ---
                            # 1. Ensure the bot is not in a squad before starting the spam.
                            # This is the critical step that was missing.
                            logging.info("Resetting bot state to solo before /sm spam.")
                            socket_client.send(self.leave_s())
                            time.sleep(0.5)  # Allow a moment for the leave command to process
                            socket_client.send(self.changes(1)) # Change mode to solo
                            time.sleep(0.5)  # Allow a moment for the mode change
                            # --- END OF THE FIX ---

                            # Create the request packet for the target player
                            invskwad_packet = self.request_join_squad(player_id_str)
                            spam_count = 30  # You can adjust this value

                            # Loop to send the packet multiple times
                            for _ in range(spam_count):
                                socket_client.send(invskwad_packet)
                                sleep(0.1)  # A small delay to prevent server issues

                            # Send a final success message
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][00FF00]Successfully Sent {spam_count} Join Requests!", uid
                                )
                            )

                            # Post-spam cleanup is still good practice.
                            sleep(1)
                            socket_client.send(self.leave_s())
                        
                        else:
                            # Handle cases where the player ID is missing or invalid
                            clients.send(
                                self.GenResponsMsg(
                                    "[C][B][FF0000]Invalid command format. Please use: /sm <player_id>", uid
                                )
                            )

                    except Exception as e:
                        logging.error(f"Error in /sm command: {e}. Restarting.")
                        try:
                            # Attempt to notify the user about the error before restarting
                            json_result = get_available_room(data.hex()[10:])
                            parsed_data = json.loads(json_result)
                            uid = parsed_data["5"]["data"]["1"]["data"]
                            clients.send(self.GenResponsMsg("[C][B][FF0000]An error occurred. Restarting bot...", uid))
                        except:
                            pass 
                        restart_program()
#-------------------------------------------------------------#                                              
                if "1200" in data.hex()[0:4] and b"/x" in data:
                    try:
                        command_split = re.split("/x ", str(data))
                        if len(command_split) > 1:
                            player_id = command_split[1].split('(')[0].strip()
                            if "***" in player_id:
                                player_id = player_id.replace("***", "106")

                            json_result = get_available_room(data.hex()[10:])
                            if not json_result:
                                logging.error("Error: Could not parse incoming packet for /x command.")
                                continue 
                            parsed_data = json.loads(json_result)
                            
                            uid = parsed_data["5"]["data"]["1"]["data"]

                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][1E90FF]6 Player Squad Spam Started for {player_id} ...!!!\n",
                                    uid
                                )
                            )

                            def squad_invite_cycle():
                                try:
                                    # Create squad
                                    packetmaker = self.skwad_maker()
                                    socket_client.send(packetmaker)
                                    sleep(0.2)

                                    # Change to 6-player squad
                                    packetfinal = self.changes(5)
                                    socket_client.send(packetfinal)

                                    # Send invite to target player
                                    invitess = self.invite_skwad(player_id)
                                    socket_client.send(invitess)

                                    # Leave squad and go back to solo to repeat the cycle
                                    sleep(0.5)
                                    leavee = self.leave_s()
                                    socket_client.send(leavee)
                                    sleep(0.2)
                                    change_to_solo = self.changes(1)
                                    socket_client.send(change_to_solo)
                                except Exception as e:
                                    logging.error(f"Error inside squad_invite_cycle: {e}")

                            invite_threads = []
                            for _ in range(29): 
                                t = threading.Thread(target=squad_invite_cycle)
                                t.start()
                                invite_threads.append(t)
                                time.sleep(0.2) 

                            for t in invite_threads:
                                t.join() 
                            
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][00FF00]Spam finished for {player_id}!",
                                    uid
                                )
                            )

                    except Exception as e:
                        logging.error(f"An unexpected error occurred in the /x command: {e}. Restarting.")
                        restart_program()                                           
#-------------------------------------------------------------#
                if "1200" in data.hex()[0:4] and b"/3" in data:
                    try:
                        i = re.split("/3", str(data))[1]
                        if "***" in i:
                            i = i.replace("***", "106")
                        sid = str(i).split("(\\x")[0]
                        
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]

                        packetmaker = self.skwad_maker()
                        socket_client.send(packetmaker)
                        sleep(0.5)

                        packetfinal = self.changes(2)
                        socket_client.send(packetfinal)
                        sleep(0.5)

                        room_data = None
                        if b'(' in data:
                            split_data = data.split(b'/3')
                            if len(split_data) > 1:
                                room_data = split_data[1].split(
                                    b'(')[0].decode().strip().split()
                                if room_data:
                                    iddd = room_data[0]
                                    invitess = self.invite_skwad(iddd)
                                    socket_client.send(invitess)
                                else:
                                    iddd = uid
                                    invitess = self.invite_skwad(iddd)
                                    socket_client.send(invitess)

                        if uid:
                            clients.send(
                                self.GenResponsMsg(
                                    f"""[00FFFF][b][c]╔══⚡ Invite Sent ⚡══╗

[FFFFFF]❤️ Accept the request quickly!\n
[FFFFFF]              3 MAN SQUAD!\n

[FF0000]╚══════════╝

[FFD700]✨ Developer —͟͞͞ </> NoTmeowl ⚡""",
                                    uid
                                )
                            )

                        sleep(5)
                        leavee = self.leave_s()
                        socket_client.send(leavee)
                        sleep(1)
                        change_to_solo = self.changes(1)
                        socket_client.send(change_to_solo)
                    except Exception as e:
                        logging.error(f"Error processing /3 command: {e}. Restarting.")
                        restart_program()
#-------------------------------------------------------------#                                        
                if "1200" in data.hex()[0:4] and b"/4" in data:
                    try:
                        i = re.split("/4", str(data))[1]
                        if "***" in i:
                            i = i.replace("***", "106")
                        sid = str(i).split("(\\x")[0]
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)

                        packetmaker = self.skwad_maker()
                        socket_client.send(packetmaker)
                        sleep(1)

                        packetfinal = self.changes(3)
                        socket_client.send(packetfinal)

                        room_data = None
                        uid = parsed_data["5"]["data"]["1"]["data"] # Define uid here
                        iddd = uid # Default to sender's id
                        if b'(' in data:
                            split_data = data.split(b'/4')
                            if len(split_data) > 1:
                                room_data = split_data[1].split(
                                    b'(')[0].decode().strip().split()
                                if room_data:
                                    iddd = room_data[0]

                        invitess = self.invite_skwad(iddd)
                        socket_client.send(invitess)

                        if uid:
                            clients.send(
                                self.GenResponsMsg(
                                    f"""[00FFFF][b][c]╔══⚡ Invite Sent ⚡══╗

[FFFFFF]❤️ Accept the request quickly!\n
[FFFFFF]              4 MAN SQUAD!\n

[FF0000]╚══════════╝

[FFD700]✨ Developer —͟͞͞ </> NoTmeowl ⚡""",
                                    uid))

                        sleep(5)
                        leavee = self.leave_s()
                        socket_client.send(leavee)
                        sleep(2)
                        change_to_solo = self.changes(1)
                        socket_client.send(change_to_solo)
                    except Exception as e:
                        logging.error(f"Error processing /4 command: {e}. Restarting.")
                        restart_program()                
#-------------------------------------------------------------#                              
                if "1200" in data.hex()[0:4] and b"/5" in data:
                    try:
                        i = re.split("/5", str(data))[1]
                        if "***" in i:
                            i = i.replace("***", "106")
                        sid = str(i).split("(\\x")[0]
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)

                        packetmaker = self.skwad_maker()
                        socket_client.send(packetmaker)
                        sleep(1)

                        packetfinal = self.changes(4)
                        socket_client.send(packetfinal)

                        room_data = None
                        uid = parsed_data["5"]["data"]["1"]["data"] # Define uid here
                        iddd = uid # Default to sender's id
                        if b'(' in data:
                            split_data = data.split(b'/5')
                            if len(split_data) > 1:
                                room_data = split_data[1].split(
                                    b'(')[0].decode().strip().split()
                                if room_data:
                                    iddd = room_data[0]

                        invitess = self.invite_skwad(iddd)
                        socket_client.send(invitess)

                        if uid:
                            clients.send(
                                self.GenResponsMsg(
                                    f"""[00FFFF][b][c]╔══⚡ Invite Sent ⚡══╗

[FFFFFF]❤️ Accept the request quickly!\n
[FFFFFF]              5 MAN SQUAD!\n

[FF0000]╚══════════╝

[FFD700]✨ Developer —͟͞͞ </> NoTmeowl⚡""",
                                    uid))

                        sleep(5)
                        leavee = self.leave_s()
                        socket_client.send(leavee)
                        sleep(2)
                        change_to_solo = self.changes(1)
                        socket_client.send(change_to_solo)
                    except Exception as e:
                        logging.error(f"Error processing /5 command: {e}. Restarting.")
                        restart_program()
#-------------------------------------------------------------#                           
                if "1200" in data.hex()[0:4] and b"/6" in data:
                    try:
                        i = re.split("/6", str(data))[1]
                        if "***" in i:
                            i = i.replace("***", "106")
                        sid = str(i).split("(\\x")[0]
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        packetmaker = self.skwad_maker()
                        socket_client.send(packetmaker)
                        sleep(0.5)
                        packetfinal = self.changes(5)
                        
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        iddd = uid
                        if b'(' in data:
                            split_data = data.split(b'/6')
                            if len(split_data) > 1:
                                room_data = split_data[1].split(
                                    b'(')[0].decode().strip().split()
                                if room_data:
                                    iddd = room_data[0]

                        socket_client.send(packetfinal)
                        invitess = self.invite_skwad(iddd)
                        socket_client.send(invitess)
                        if uid:
                            clients.send(
                                self.GenResponsMsg(
                        f"""[00FFFF][b][c]╔══⚡ Invite Sent ⚡══╗

[FFFFFF]❤️ Accept the request quickly!\n
[FFFFFF]              6 MAN SQUAD!\n

[FF0000]╚══════════╝

[FFD700]✨ Developer —͟͞͞ </> NoTmeowl ⚡""",
                                    uid))

                        sleep(4)
                        leavee = self.leave_s()
                        socket_client.send(leavee)
                        sleep(0.5)
                        change_to_solo = self.changes(1)
                        socket_client.send(change_to_solo)
                    except Exception as e:
                        logging.error(f"Error processing /6 command: {e}. Restarting.")
                        restart_program()
#-------------------------------------------------------------#
                if "1200" in data.hex()[0:4] and b"/change" in data:
                    try:
                        # Get the UID of the user who sent the command to send a reply
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]

                        # Parse the command to get the desired action (e.g., "6" or "spm")
                        command_parts = data.split(b'/change')[1].split(b'(')[0].decode().strip().split()

                        # Check if an argument was provided
                        if not command_parts:
                            clients.send(
                                self.GenResponsMsg(
                                    "[C][B][FF0000]Usage: /change <size_or_spm>\nExamples:\n/change 6\n/change spm", uid
                                )
                            )
                            continue

                        # The sub-command is the first argument (e.g., '6' or 'spm')
                        sub_command = command_parts[0].lower() # .lower() makes it case-insensitive

                        # --- Handler for the 'spm' sub-command ---
                        if sub_command == "spm":
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][FFA500]Starting team size spam (5-6) for 15 cycles...", uid
                                )
                            )

                            # Loop 15 times to spam the team size change
                            for i in range(15):
                                socket_client.send(self.changes(5)) # Change to 6-player squad
                                time.sleep(0.2)
                                socket_client.send(self.changes(4)) # Change to 5-player squad
                                time.sleep(0.2)

                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][00FF00]Team size spam completed!", uid
                                )
                            )
                        
                        # --- Handler for a specific team size number ---
                        elif sub_command.isdigit():
                            team_size = int(sub_command)
                            
                            # Maps the desired team size to the correct parameter for the self.changes() function
                            size_to_param_map = {3: 2, 4: 3, 5: 4, 6: 5}

                            # Check if the requested size is a valid option
                            if team_size not in size_to_param_map:
                                clients.send(
                                    self.GenResponsMsg(
                                        f"[C][B][FF0000]Invalid team size. Please choose 3, 4, 5, or 6.", uid
                                    )
                                )
                                continue
                            
                            change_param = size_to_param_map[team_size]
                            
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][FFFF00]Attempting to change team size to {team_size}...", uid
                                )
                            )

                            # Send the packet to change the team mode
                            socket_client.send(self.changes(change_param))
                            time.sleep(0.5) # Allow time for the change to process

                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][00FF00]Successfully changed team mode to a {team_size}-player squad!", uid
                                )
                            )
                        
                        # --- Handler for any other invalid input ---
                        else:
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][FF0000]Invalid command. Use a number (3-6) or 'spm'.", uid
                                )
                            )

                    except Exception as e:
                        logging.error(f"Error processing /change command: {e}. Restarting.")
                        try:
                            json_result = get_available_room(data.hex()[10:])
                            parsed_data = json.loads(json_result)
                            uid = parsed_data["5"]["data"]["1"]["data"]
                            clients.send(self.GenResponsMsg("[C][B][FF0000]An error occurred with /change. Restarting...", uid))
                        except:
                            pass
                        restart_program()
#-------------------------------------------------------------#
                if "1200" in data.hex()[0:4] and b"/team" in data:
                    try:
                        # Decode the incoming data, ignoring errors and removing null characters
                        raw_message = data.decode('utf-8', errors='ignore')
                        cleaned_message = raw_message.replace('\x00', '').strip()
                        
                        # Set a default ID in case one is not provided or is invalid
                        default_id = "2060437760"
                        team_uid = default_id
                        
                        # Use regex to find a valid player ID after the /team command
                        id_match = re.search(r'/team\s*(\d{5,15})\b', cleaned_message)
                        if id_match:
                            # If a match is found, use it as the target UID
                            team_uid = id_match.group(1)
                        
                        # Get the sender's UID to send a response
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]

                        # Send a confirmation message that the spam is starting
                        clients.send(
                            self.GenResponsMsg(
                                f"[00FF00][b][c]TEAM SPAM STARTED FOR 10 SECONDS ON UID: {fix_num(team_uid)}", 
                                uid
                            )
                        )

                        start_time = time.time()
                        
                        # Run the spam loop for 10 seconds
                        while time.time() - start_time < 10:
                            # Create a squad
                            packetmaker = self.skwad_maker()
                            socket_client.send(packetmaker)
                            sleep(0.05)
                            
                            # Change to 5-player mode
                            packetfinal_5 = self.changes(4)
                            socket_client.send(packetfinal_5)
                            
                            # Send the invite
                            invitess = self.invite_skwad(team_uid)
                            socket_client.send(invitess)

                            sleep(0.05)
                            # Change to 6-player mode
                            packetfinal_6 = self.changes(5)
                            socket_client.send(packetfinal_6)
                        
                        # After the loop finishes, leave the squad
                        leavee = self.leave_s()
                        socket_client.send(leavee)
                        
                        # Send a final confirmation message
                        clients.send(
                            self.GenResponsMsg(
                                f"[00FF00][b][c]TEAM SPAM COMPLETED FOR UID: {fix_num(team_uid)}", 
                                uid
                            )
                        )

                    except Exception as e:
                        # Log the error for debugging
                        logging.error(f"Error in /team command: {e}. Restarting.")
                        
                        # Try to inform the user about the error before restarting
                        try:
                            json_result = get_available_room(data.hex()[10:])
                            parsed_data = json.loads(json_result)
                            uid = parsed_data["5"]["data"]["1"]["data"]
                            clients.send(
                                self.GenResponsMsg(
                                    f"[FF0000]An error occurred in the /team command. The bot will restart.", 
                                    uid
                                )
                            )
                        except:
                            # If sending the message fails, just proceed with the restart
                            pass
                        
                        # Restart the program to ensure stability
                        restart_program()
#-------------------------------------------------------------#                                
                if "1200" in data.hex()[0:4] and b"/status" in data:
                    try:
                        i = re.split("/status", str(data))[1]
                        if "***" in i:
                            i = i.replace("***", "106")
                        sid = str(i).split("(\\x")[0]
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        split_data = re.split(rb'/status', data)
                        room_data = split_data[1].split(b'(')[0].decode().strip().split()
                        if room_data:
                            player_id = room_data[0]
                            packetmaker = self.createpacketinfo(player_id)
                            socket_client.send(packetmaker)
                            statusinfo1 = True
                            while statusinfo1:
                                if statusinfo == True:
                                    if "IN ROOM" in tempdata:
                                        inforoooom = self.info_room(data22)
                                        socket_client.send(inforoooom)
                                        sleep(0.5)
                                        clients.send(self.GenResponsMsg(f"{tempdata1}", uid))  
                                        tempdata = None
                                        tempdata1 = None
                                        statusinfo = False
                                        statusinfo1 = False
                                    else:
                                        clients.send(self.GenResponsMsg(f"{tempdata}", uid))  
                                        tempdata = None
                                        tempdata1 = None
                                        statusinfo = False
                                        statusinfo1 = False
                        else:
                            clients.send(self.GenResponsMsg("[C][B][FF0000] Please enter a player ID!", uid))  
                    except Exception as e:
                        logging.error(f"Error in /status command: {e}. Restarting.")
                        try:
                            json_result = get_available_room(data.hex()[10:])
                            uid = json.loads(get_available_room(data.hex()[10:]))["5"]["data"]["1"]["data"]
                            clients.send(self.GenResponsMsg("[C][B][FF0000]ERROR! Bot will restart.", uid))
                        except:
                            pass
                        restart_program()
#-------------------------------------------------------------#                             
                if "1200" in data.hex()[0:4] and b"/inv" in data and not (b"/i " in data or data.endswith(b"/i") or data.endswith(b"/i\n")):
                    try:
                        i = re.split("/inv", str(data))[1]
                        if "***" in i:
                            i = i.replace("***", "106")
                        sid = str(i).split("(\\x")[0]
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        split_data = re.split(rb'/inv', data)
                        room_data = split_data[1].split(b'(')[0].decode().strip().split()
                        if room_data:
                            iddd = room_data[0]
                            numsc1 = "5"

                            if numsc1 is None:
                                clients.send(
                                    self.GenResponsMsg(
                                        f"[C][B] [FF00FF]Please write id and count of the group\n[ffffff]Example : \n/inv 123[c]456[c]78 4\n/inv 123[c]456[c]78 5", uid
                                    )
                                )
                            else:
                                numsc = int(numsc1) - 1
                                if int(numsc1) < 3 or int(numsc1) > 6:
                                    clients.send(
                                        self.GenResponsMsg(
                                            f"[C][B][FF0000] Usage : /inv <uid> <Squad Type>\n[ffffff]Example : \n/inv 12345678 4\n/inv 12345678 5", uid
                                        )
                                    )
                                else:
                                    packetmaker = self.skwad_maker()
                                    socket_client.send(packetmaker)
                                    sleep(1)
                                    packetfinal = self.changes(int(numsc))
                                    socket_client.send(packetfinal)
                                    
                                    invitess = self.invite_skwad(iddd)
                                    socket_client.send(invitess)
                                    iddd1 = parsed_data["5"]["data"]["1"]["data"]
                                    invitessa = self.invite_skwad(iddd1)
                                    socket_client.send(invitessa)
                                    clients.send(
                                self.GenResponsMsg(
                                    f"[C][B][00ff00]Team creation is in progress and the invite has been sent! ", uid
                                )
                            )

                        sleep(5)
                        leavee = self.leave_s()
                        socket_client.send(leavee)
                        sleep(5)
                        change_to_solo = self.changes(1)
                        socket_client.send(change_to_solo)
                        sleep(0.1)
                        clients.send(
                            self.GenResponsMsg(
                                f"[C][B] [FF00FF]Bot is now in solo mode.", uid
                            )
                        )
                    except Exception as e:
                        logging.error(f"Error processing /inv command: {e}. Restarting.")
                        restart_program()
#-------------------------------------------------------------#                        
                if "1200" in data.hex()[0:4] and b"/room" in data:
                    try:
                        i = re.split("/room", str(data))[1] 
                        sid = str(i).split("(\\x")[0]
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        split_data = re.split(rb'/room', data)
                        room_data = split_data[1].split(b'(')[0].decode().strip().split()
                        if room_data:
                            
                            player_id = room_data[0]
                            if player_id.isdigit():
                                if "***" in player_id:
                                    player_id = rrrrrrrrrrrrrr(player_id)
                                packetmaker = self.createpacketinfo(player_id)
                                socket_client.send(packetmaker)
                                sleep(0.5)
                                if "IN ROOM" in tempdata:
                                    room_id = get_idroom_by_idplayer(data22)
                                    packetspam = self.spam_room(room_id, player_id)
                                    #logging.info(packetspam.hex())
                                    clients.send(
                                        self.GenResponsMsg(
                                            f"[C][B][00ff00]Working on your request for {fix_num(player_id)} ! ", uid
                                        )
                                    )
                                    
                                    
                                    for _ in range(99):

                                        #logging.info(" sending spam to "+player_id)
                                        threading.Thread(target=socket_client.send, args=(packetspam,)).start()
                                    
                                    
                                    
                                    clients.send(
                                        self.GenResponsMsg(
                                            f"[C][B] [00FF00]Request successful! ✅", uid
                                        )
                                    )
                                else:
                                    clients.send(
                                        self.GenResponsMsg(
                                            f"[C][B] [FF00FF]The player is not in a room", uid
                                        )
                                    )      
                            else:
                                clients.send(
                                    self.GenResponsMsg(
                                        f"[C][B] [FF00FF]Please write the player's ID!", uid
                                    )
                                )   

                        else:
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B] [FF00FF]Please write the player's ID !", uid
                                )
                            )   
                    except Exception as e:
                        logging.error(f"Error processing /room command: {e}. Restarting.")
                        restart_program()

                if "1200" in data.hex()[0:4] and b"xr" in data:
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        client_id = parsed_data["5"]["data"]["1"]["data"]

                        clients.send(
                            self.GenResponsMsg(
                                f"[C][B][1E90FF]Started Reject Spam on: {fix_num(client_id)}",
                                client_id
                            )
                        )

                        for _ in range(150):
                            socket_client.send(self.NoTmeowl1(client_id))
                            socket_client.send(self.NoTmeowl(client_id))
                            time.sleep(0.2)

                        clients.send(
                            self.GenResponsMsg(
                                f"[C][B][00FF00]✅ Reject Spam Completed Successfully for ID {fix_num(client_id)}",
                                client_id
                            )
                        )

                    except Exception as e:
                        logging.error(f"[WHISPER] Error in xr command: {e}")
                        clients.send(
                            self.GenResponsMsg(
                                f"[C][B][FF0000]❌ Error: {e}",
                                client_id
                            )
                        )
#-------------------------------------------------------------#          
                if "1200" in data.hex()[0:4] and b"[FFFFF00]NoTmeowl  [ffffff]XR" in data:
                    pass
                else:
                
                    if "1200" in data.hex()[0:4] and b"/spam" in data:
                        try:
                            command_split = re.split("/spam", str(data))
                            if len(command_split) > 1:
                                player_id = command_split[1].split('(')[0].strip()
                                #logging.info(f"Sending Spam To {player_id}")
                                json_result = get_available_room(data.hex()[10:])
                                parsed_data = json.loads(json_result)
                                uid = parsed_data["5"]["data"]["1"]["data"]
                                clients.send(
                                self.GenResponsMsg(
                                    f"{generate_random_color()}Sending friend requests...", uid
                                )
                            )
                                
                                message = send_spam(player_id)
                                #logging.info(message)
                                json_result = get_available_room(data.hex()[10:])
                                parsed_data = json.loads(json_result)
                                uid = parsed_data["5"]["data"]["1"]["data"]
                                
                                clients.send(self.GenResponsMsg(message, uid))
                        except Exception as e:
                            logging.error(f"Error processing /spam command: {e}. Restarting.")
                            restart_program()
#-------------------------------------------------------------#                            
                    if "1200" in data.hex()[0:4] and b"/visit" in data and not (b"/v " in data or data.endswith(b"/v") or data.endswith(b"/v\n")):
                        try:
                            command_split = re.split("/visit", str(data))
                            if len(command_split) > 1:
                                player_id = command_split[1].split('(')[0].strip()

                                #logging.info(f"[C][B]Sending visit To {player_id}")
                                json_result = get_available_room(data.hex()[10:])
                                parsed_data = json.loads(json_result)
                                uid = parsed_data["5"]["data"]["1"]["data"]
                                clients.send(
                    self.GenResponsMsg(
                        f"{generate_random_color()}Sending 1000 visits to {fix_num(player_id)}...", uid
                                    )
                                )
                                
                                message = send_vistttt(player_id)
                                json_result = get_available_room(data.hex()[10:])
                                parsed_data = json.loads(json_result)
                                uid = parsed_data["5"]["data"]["1"]["data"]
                                
                                clients.send(self.GenResponsMsg(message, uid))
                        except Exception as e:
                            logging.error(f"Error processing /visit command: {e}. Restarting.")
                            restart_program()	                           
#-------------------------------------------------------------#           
                    if "1200" in data.hex()[0:4] and b"/info" in data and not (b"/inf " in data or data.endswith(b"/inf") or data.endswith(b"/inf\n")):
                        try:
                            # Extract the sender's ID to send the reply back
                            json_result = get_available_room(data.hex()[10:])
                            parsed_data = json.loads(json_result)
                            sender_id = parsed_data["5"]["data"]["1"]["data"]

                            # Extract the target ID from the user's message
                            command_split = re.split("/info", str(data))
                            if len(command_split) <= 1 or not command_split[1].strip():
                                clients.send(self.GenResponsMsg("[C][B][FF0000] Please provide a player ID after the command.", sender_id))
                                continue

                            # Find the first valid-looking number string in the command text
                            uids = re.findall(r"\b\d{5,15}\b", command_split[1])
                            uid_to_check = uids[0] if uids else ""

                            if not uid_to_check:
                                clients.send(self.GenResponsMsg("[C][B][FF0000] Invalid or missing Player ID.", sender_id))
                                continue
                            
                            clients.send(self.GenResponsMsg(f"[C][B][FFFF00]✅ Request received! Fetching info for {fix_num(uid_to_check)}...", sender_id))
                            time.sleep(0.5)

                            # Call the new info function
                            info_response = newinfo(uid_to_check)
                            
                            if info_response.get('status') != "ok":
                                clients.send(self.GenResponsMsg("[C][B][FF0000]❌ Wrong ID or API error. Please double-check the ID.", sender_id))
                                continue

                            info = info_response['info']

                            # --- Message 1: Basic Account Info ---
                            player_info_msg = (
                                f"[C][B][00FF00]━━「 Player Information 」━━\n"
                                f"[FFA500]• Name: [FFFFFF]{info.get('AccountName', 'N/A')}\n"
                                f"[FFA500]• Level: [FFFFFF]{info.get('AccountLevel', 'N/A')}\n"
                                f"[FFA500]• Likes: [FFFFFF]{fix_num(info.get('AccountLikes', 0))}\n"
                                f"[FFA500]• UID: [FFFFFF]{fix_num(info.get('accountId', 'N/A'))}\n"
                                f"[FFA500]• Region: [FFFFFF]{info.get('AccountRegion', 'N/A')}"
                            )
                            clients.send(self.GenResponsMsg(player_info_msg, sender_id))
                            time.sleep(0.5)

                            # --- Message 2: Rank and Signature ---
                            rank_info_msg = (
                                f"[C][B][00BFFF]━━「 Rank & Status 」━━\n"
                                f"[FFA500]• BR Rank: [FFFFFF]{info.get('BrMaxRank', 'N/A')} ({info.get('BrRankPoint', 0)} pts)\n"
                                f"[FFA500]• CS Rank: [FFFFFF]{info.get('CsMaxRank', 'N/A')} ({info.get('CsRankPoint', 0)} pts)\n"
                                f"[FFA500]• Bio: [FFFFFF]{info.get('signature', 'No Bio').replace('|', ' ')}"
                            )
                            clients.send(self.GenResponsMsg(rank_info_msg, sender_id))
                            time.sleep(0.5)

                            # --- Message 3: Guild Info (only if the player is in a guild) ---
                            if info.get('GuildID') and info.get('GuildID') != "0":
                                guild_info_msg = (
                                    f"[C][B][FFD700]━━「 Guild Information 」━━\n"
                                    f"[FFA500]• Name: [FFFFFF]{info.get('GuildName', 'N/A')}\n"
                                    f"[FFA500]• ID: [FFFFFF]{fix_num(info.get('GuildID', 'N/A'))}\n"
                                    f"[FFA500]• Members: [FFFFFF]{info.get('GuildMember', 0)}/{info.get('GuildCapacity', 0)}\n"
                                    f"[FFA500]• Level: [FFFFFF]{info.get('GuildLevel', 'N/A')}"
                                )
                                clients.send(self.GenResponsMsg(guild_info_msg, sender_id))
                            else:
                                clients.send(self.GenResponsMsg("[C][B][FFD700]Player is not currently in a guild.", sender_id))

                        except Exception as e:
                            logging.error(f"CRITICAL ERROR in /info command: {e}. Restarting bot.")
                            # Attempt to notify the user of the crash before restarting
                            try:
                                json_result = get_available_room(data.hex()[10:])
                                parsed_data = json.loads(json_result)
                                sender_id = parsed_data["5"]["data"]["1"]["data"]
                                clients.send(self.GenResponsMsg("[C][B][FF0000]A critical error occurred. The bot will restart now.", sender_id))
                            except:
                                pass # Ignore if sending the error message also fails
                            restart_program()
#-------------------------------------------------------------#	                    
                    if "1200" in data.hex()[0:4] and b"/likes" in data and not (b"/lk " in data or data.endswith(b"/lk") or data.endswith(b"/lk\n")):
                        try:
                            json_result = get_available_room(data.hex()[10:])
                            parsed_data = json.loads(json_result)
                            uid = parsed_data["5"]["data"]["1"]["data"]
                            clients.send(
                                self.GenResponsMsg(
                                    f"{generate_random_color()}The request is being processed.", uid
                                )
                            )
                            command_split = re.split("/likes", str(data))
                            player_id = command_split[1].split('(')[0].strip()
                            
                            # This part works perfectly with the new function
                            likes_response = send_likes(player_id)
                            message = likes_response['message']
                            clients.send(self.GenResponsMsg(message, uid))

                        except Exception as e:
                            logging.error(f"Error processing /likes command: {e}. Restarting.")
                            restart_program()
#-------------------------------------------------------------#
                    if "1200" in data.hex()[0:4] and b"/help" in data:
                        try:
                            json_result = get_available_room(data.hex()[10:])
                            parsed_data = json.loads(json_result)
                            uid = parsed_data["5"]["data"]["1"]["data"]
                            
                            clients.send(
                                self.GenResponsMsg(
                                        f"""[C][B][FFD700]═══⚓︎ NoTmeowl'S BOT | HELP 1/4 ⚓︎═══[00FF00][B]
[FFFFFF]⚡ COMANDOS ABREVIADOS (FÁCILES):
[00FFFF]⚡/e [número] - Emote evolutiva (auto UID)
[00FFFF]⚡/p [número] - Play emote (auto UID)
[00FFFF]⚡/n [emote_id] - Spam emote (auto UID)
[00FFFF]⚡/i [UID] - Invitar a squad
[00FFFF]⚡/s [UID] - Spam amistad
[00FFFF]⚡/v [UID] - Visitas
[00FFFF]⚡/lk [UID] - Likes
[00FFFF]⚡/inf [UID] - Info jugador
[00FFFF]⚡/j [TeamCode] - Join sala
[00FFFF]⚡/a [TeamCode] - Attack sala
[00FFFF]⚡/t [UID] - Team spam
[00FFFF]━━━━━━━━━━━━
[00FF00]

""", uid
                                )
                            )
                            time.sleep(0.2)
                            clients.send(
                                    self.GenResponsMsg(
                                        f"""[C][B][FFD700]═══⚓︎ NoTmeowl'S BOT | HELP 2/4 ⚓︎═══[00FF00][B]
[FFFFFF]⚡ SQUAD/GRUPO:
[00FFFF]⚡/join [TeamCode] - Unirse a sala
[00FFFF]⚡/solo - Salir a modo solo
[00FFFF]⚡/inv [UID] [Tipo] - Invitar a squad
[00FFFF]⚡/3, /4, /5, /6 [UID] - Crear squad
[00FFFF]⚡/change [3-6/spm] - Cambiar tamaño
[FFFFFF]⚡ SPAM/ATAQUE:
[00FFFF]⚡/spam [uid] - Spam amistad
[00FFFF]⚡/sm [uid] - Spam invite
[00FFFF]⚡/attack [teamcode] - Ataque sala
[00FFFF]⚡/x [uid] - Spam squad 6
[00FFFF]━━━━━━━━━━━━
[00FF00] """, uid
                                    )
                                )
                            time.sleep(0.2)
                            clients.send(
                                    self.GenResponsMsg(
                                        f"""[C][B][FFD700]═══⚓︎ NoTmeowl'S BOT | HELP 3/4 ⚓︎═══[00FF00][B]
[FFFFFF]⚡ EMOTES:
[00FFFF]⚡/play [uid] [número] - Emote por número
[00FFFF]⚡/ev [uid] [1-17] - Emote evolutiva
[00FFFF]⚡/nm [uid] [emote_id] - Spam emote
[FFFFFF]⚡ SOCIAL:
[00FFFF]⚡/likes [uid] - Agregar likes
[00FFFF]⚡/visit [uid] - Enviar visitas
[00FFFF]⚡/info [uid] - Info jugador
[00FFFF]⚡/status [uid] - Estado jugador
[00FFFF]⚡/room [uid] - Solicitar sala
[00FFFF]━━━━━━━━━━━━
[00FF00] """, uid
                                    )
                                )
                            time.sleep(0.2)
                            clients.send(
                                    self.GenResponsMsg(
                                        f"""[C][B][FFD700]═══⚓︎ NoTmeowl'S BOT | HELP 4/4 ⚓︎═══[00FF00][B]
[FFFFFF]⚡ ESPECIALES:
[00FFFF]⚡/ai [texto] - Chat con IA
[00FFFF]⚡/help - Mostrar ayuda
[00FFFF]⚡/admin - Info desarrollador
[FFFFFF]⚡ NOTA:
[00FFFF]Los comandos abreviados (/e, /p, /n, etc.)
[00FFFF]detectan automáticamente tu UID si no lo especificas
[00FFFF]Ejemplo: /e 10 (emote evolutiva #10 a ti mismo)
[00FFFF]━━━━━━━━━━━━
[00FF00] """, uid
                                    )
                                )
                        except Exception as e:
                            logging.error(f"Error processing /help command: {e}. Restarting.")
                            restart_program()                    
#-------------------------------------------------------------#
                    if "1200" in data.hex()[0:4] and b"/ai" in data:
                        try:
                            i = re.split("/ai", str(data))[1]
                            if "***" in i:
                                i = i.replace("***", "106")
                            sid = str(i).split("(\\x")[0].strip()
                            headers = {"Content-Type": "application/json"}
                            payload = {
                                "contents": [
                                    {
                                        "parts": [
                                            {"text": sid}
                                        ]
                                    }
                                ]
                            }
                            global http_session
                            response = http_session.post(
                                f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=AIzaSyDZvi8G_tnMUx7loUu51XYBt3t9eAQQLYo",
                                headers=headers,
                                json=payload,
                                timeout=30
                            )
                            if response.status_code == 200:
                                ai_data = response.json()
                                ai_response = ai_data['candidates'][0]['content']['parts'][0]['text']
                                json_result = get_available_room(data.hex()[10:])
                                parsed_data = json.loads(json_result)
                                uid = parsed_data["5"]["data"]["1"]["data"]
                                clients.send(
                                    self.GenResponsMsg(
                                        ai_response, uid
                                    )
                                )
                            else:
                                logging.error(f"Error with AI API: {response.status_code} {response.text}")
                        except Exception as e:
                            logging.error(f"Error processing /ai command: {e}. Restarting.")
                            restart_program()
#-------------------------------------------------------------#
                if '1200' in data.hex()[0:4] and b'/join' in data:
                    try:
                        # Split the incoming data using the new command '/join tc'
                        split_data = re.split(rb'/join', data)
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data['5']['data']['1']['data']
                        
                        # Get the command parts, which should be the room ID
                        command_parts = split_data[1].split(b'(')[0].decode().strip().split()

                        # Check if a room ID was provided
                        if not command_parts:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Please provide a room code.", uid))
                            continue

                        # The first part of the command is the room ID
                        room_id = command_parts[0]
                        
                        clients.send(
                            self.GenResponsMsg(f"[C][B][32CD32]Attempting to join room: {room_id}", uid)
                        )
                        
                        # Call the join function a single time
                        join_teamcode(socket_client, room_id, key, iv)
                        
                        # Optional: Add a small delay to ensure the join command is processed
                        time.sleep(0.1)

                        clients.send(
                            self.GenResponsMsg(f"[C][B][00FF00]Successfully joined the room.", uid)
                        )

                    except Exception as e:
                        # Updated the error message to reflect the new command name
                        logging.error(f"An error occurred during /join: {e}. Restarting.")
                        restart_program()
#-------------------------------------------------------------#
                if '1200' in data.hex()[0:4] and b'/lag' in data:
                    try:
                        split_data = re.split(rb'/lag', data)
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data['5']['data']['1']['data']
                        command_parts = split_data[1].split(b'(')[0].decode().strip().split()

                        if not command_parts:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Please provide a code.", uid))
                            continue

                        room_id = command_parts[0]
                        repeat_count = 1
                        if len(command_parts) > 1 and command_parts[1].isdigit():
                            repeat_count = int(command_parts[1])
                        if repeat_count > 3:
                            repeat_count = 3
                        
                        clients.send(
                            self.GenResponsMsg(f"[C][B][32CD32]Starting spam process. Will repeat {repeat_count} time(s).", uid)
                        )
                        
                        for i in range(repeat_count):
                            if repeat_count > 1:
                                clients.send(self.GenResponsMsg(f"[C][B][FFA500]Running batch {i + 1} of {repeat_count}...", uid))

                            for _ in range(11111):
                                join_teamcode(socket_client, room_id, key, iv)
                                time.sleep(0.001)
                                leavee = self.leave_s()
                                socket_client.send(leavee)
                                time.sleep(0.0001)
                            
                            if repeat_count > 1 and i < repeat_count - 1:
                                time.sleep(0.1)

                        clients.send(
                            self.GenResponsMsg(f"[C][B][00FF00]Your order has been confirmed", uid)
                        )
                    except Exception as e:
                        logging.error(f"An error occurred during /lag spam: {e}. Restarting.")
                        restart_program()
#-------------------------------------------------------------#
                if "1200" in data.hex()[0:4] and b"/solo" in data:
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        leavee = self.leave_s()
                        socket_client.send(leavee)
                        sleep(1)
                        change_to_solo = self.changes(1)
                        socket_client.send(change_to_solo)
                        clients.send(
                            self.GenResponsMsg(
                                f"[C][B][00FF00] Exited from the group. ", uid
                            )
                        )
                    except Exception as e:
                        logging.error(f"Error processing /solo command: {e}. Restarting.")
                        restart_program()
#-------------------------------------------------------------#                        
                if '1200' in data.hex()[0:4] and b'/attack' in data:
                    try:
                        split_data = re.split(rb'/attack', data)
                        command_parts = split_data[1].split(b'(')[0].decode().strip().split()
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data['5']['data']['1']['data']

                        if not command_parts:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]With this, you can join and attack any group \n/attack [TeamCode]", uid))
                            continue

                        team_code = command_parts[0]
                        clients.send(
                            self.GenResponsMsg(f"[C][B][FFA500]Join attack has started on Team Code {team_code}...", uid)
                        )

                        start_packet = self.start_autooo()
                        leave_packet = self.leave_s()
                        attack_start_time = time.time()
                        while time.time() - attack_start_time < 45:
                            join_teamcode(socket_client, team_code, key, iv)
                            socket_client.send(start_packet)
                            socket_client.send(leave_packet)
                            time.sleep(0.15)

                        clients.send(
                            self.GenResponsMsg(f"[C][B][00FF00]Double attack on the team is complete! ✅   {team_code}!", uid)
                        )

                    except Exception as e:
                        logging.error(f"An error occurred in /attack command: {e}. Restarting.")
                        restart_program()
#-------------------------------------------------------------#
                if "1200" in data.hex()[0:4] and b"/play" in data:
                    try:
                        # --- START: Load Emotes from JSON file ---
                        emote_map = {}
                        try:
                            # This will open and read the emotes.json file.
                            # Make sure emotes.json is in the same folder as your app.py file!
                            with open('emotes.json', 'r') as f:
                                emotes_data = json.load(f)
                                # This loop converts the data from the file into the dictionary format the bot needs.
                                for emote_entry in emotes_data:
                                    emote_map[emote_entry['Number']] = emote_entry['Id']
                        
                        except FileNotFoundError:
                            logging.error("CRITICAL: emotes.json file not found! The /play command is disabled.")
                            # If the file doesn't exist, inform the user.
                            json_result = get_available_room(data.hex()[10:])
                            uid_sender = json.loads(json_result)["5"]["data"]["1"]["data"]
                            clients.send(self.GenResponsMsg(
                                "[C][B][FF0000]Error: emotes.json file is missing. Please contact the admin.", uid_sender
                            ))
                            continue # Stop processing the command
                        
                        except (json.JSONDecodeError, KeyError):
                            logging.error("CRITICAL: emotes.json is formatted incorrectly! The /play command is disabled.")
                            # If the file is broken or has the wrong format, inform the user.
                            json_result = get_available_room(data.hex()[10:])
                            uid_sender = json.loads(json_result)["5"]["data"]["1"]["data"]
                            clients.send(self.GenResponsMsg(
                                "[C][B][FF0000]Error: Emote data file is corrupted. Please contact the admin.", uid_sender
                            ))
                            continue # Stop processing the command
                        # --- END: Load Emotes from JSON file ---

                        # Get the sender's UID to send replies
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid_sender = parsed_data["5"]["data"]["1"]["data"]

                        # Parse the command parts
                        command_parts = data.split(b'/play')[1].split(b'(')[0].decode().strip().split()
                        
                        if len(command_parts) < 2:
                            clients.send(self.GenResponsMsg(
                                f"[C][B][FF0000]Usage: /play <target_id> <emote_number>", uid_sender
                            ))
                            continue

                        emote_choice = command_parts[-1]
                        target_ids = command_parts[:-1]
                        
                        # Dynamically check if the chosen emote number is valid
                        if emote_choice not in emote_map:
                            max_emote_number = len(emote_map)
                            clients.send(self.GenResponsMsg(
                                f"[C][B][FF0000]Invalid emote number. Please use a number between 1 and {max_emote_number}.", uid_sender
                            ))
                            continue
                        
                        emote_id_to_send = emote_map[emote_choice]

                        clients.send(self.GenResponsMsg(
                            f"[C][B][00FF00]Sending emote #{emote_choice} to {len(target_ids)} player(s)...", uid_sender
                        ))
                        
                        # Verify socket is connected
                        try:
                            socket_client.getpeername()
                            logging.info(f"[SOCKET] Socket Online conectado correctamente para /play")
                        except Exception as e:
                            logging.error(f"[ERROR SOCKET] Socket no conectado: {e}")
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Error: Socket no conectado. El bot se reiniciará.", uid_sender))
                            restart_program()
                            continue
                        
                        # Loop through all provided target IDs
                        for target_id in target_ids:
                            if target_id.isdigit() and emote_id_to_send.isdigit():
                                logging.info(f"[CREANDO PAQUETE] Target: {target_id} | Emote ID: {emote_id_to_send} (número: {emote_choice})")
                                emote_packet = self.send_emote(target_id, emote_id_to_send)
                                
                                # Send the emote once and wait 5 seconds for it to complete
                                logging.info(f"[ENVIANDO] Enviando emote #{emote_choice} una vez y esperando 5 segundos...")
                                socket_client.send(emote_packet)
                                
                                # Wait 5 seconds for the emote animation to complete
                                time.sleep(5.0)
                                
                                logging.info(f"[OK] Emote #{emote_choice} completado (5 segundos) para {target_id}")
                        
                        clients.send(self.GenResponsMsg(
                            f"[C][B][00FF00]Emote #{emote_choice} completed successfully!", uid_sender
                        ))

                    except Exception as e:
                        logging.error(f"Error processing /play command: {e}. Restarting.")
                        try:
                            json_result = get_available_room(data.hex()[10:])
                            uid = json.loads(json_result)["5"]["data"]["1"]["data"]
                            clients.send(self.GenResponsMsg("[C][B][FF0000]An error occurred with /play. Restarting...", uid))
                        except:
                            pass
                        restart_program()
#-------------------------------------------------------------#                                
                if "1200" in data.hex()[0:4] and b"/ev" in data:
                    try:
                        logging.info(f"[COMANDO RECIBIDO] /ev detectado")
                        # Step 1: Get the sender's UID for replies
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid_sender = parsed_data["5"]["data"]["1"]["data"]
                        logging.info(f"[USUARIO] UID del remitente: {uid_sender}")

                        # Step 2: Parse the command parts safely
                        command_parts = data.split(b'/ev')[1].split(b'(')[0].decode().strip().split()
                        logging.info(f"[PARAMETROS] /ev con parametros: {command_parts}")

                        # Step 3: Validate the number of arguments
                        if len(command_parts) < 2:
                            logging.warning(f"[WARNING] /ev con parametros insuficientes")
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Usage: /ev <player_id> <number>", uid_sender))
                            continue
                        
                        # Step 4: Assign arguments robustly
                        # The last item is the emote choice, the first is the target ID.
                        evo_choice = command_parts[-1] 
                        target_id = command_parts[0]
                        logging.info(f"[PARSING] Target ID: {target_id} | EVO Choice: {evo_choice}")

                        # Step 5: Define the mapping of choices to emote IDs
                        evo_emotes = {
                            "1": "909000063",   # AK
                            "2": "909000068",   # SCAR
                            "3": "909000075",   # 1st MP40
                            "4": "909040010",   # 2nd MP40
                            "5": "909000081",   # 1st M1014
                            "6": "909039011",   # 2nd M1014
                            "7": "909000085",   # XM8
                            "8": "909000090",   # Famas
                            "9": "909000098",   # UMP
                            "10": "909035007",  # M1887
                            "11": "909042008",  # Woodpecker
                            "12": "909041005",  # Groza
                            "13": "909033001",  # M4A1
                            "14": "909038010",  # Thompson
                            "15": "909038012",  # G18
                            "16": "909045001",  # Parafal
                            "17": "909049010"   # P90
                        }
                        emote_id = evo_emotes.get(evo_choice)
                        logging.info(f"[EMOTE ID] Mapeo: {evo_choice} -> {emote_id}")

                        # Step 6: Validate the chosen number. If it's not in the dictionary, emote_id will be None.
                        if not emote_id:
                            logging.warning(f"[ERROR] Emote choice invalido: {evo_choice}")
                            clients.send(self.GenResponsMsg(f"[C][B][FF0000]Invalid choice: {evo_choice}. Please use a number from 1-17.", uid_sender))
                            continue

                        # Step 7: Validate IDs and send the action packet
                        if target_id.isdigit() and emote_id.isdigit():
                            logging.info(f"[CREANDO PAQUETE] Target: {target_id} | Emote ID: {emote_id}")
                            
                            # Verify socket is connected
                            try:
                                socket_client.getpeername()
                                logging.info(f"[SOCKET] Socket Online conectado correctamente")
                            except Exception as e:
                                logging.error(f"[ERROR SOCKET] Socket no conectado: {e}")
                                clients.send(self.GenResponsMsg("[C][B][FF0000]Error: Socket no conectado. El bot se reiniciará.", uid_sender))
                                restart_program()
                                continue
                            
                            # Create the game action packet
                            emote_packet = self.send_emote(target_id, emote_id)
                            logging.info(f"[PAQUETE CREADO] Tamaño: {len(emote_packet)} bytes | Hex (primeros 40): {emote_packet.hex()[:40]}")
                            
                            # Send the action to the game server multiple times (like /nm does)
                            # This ensures the emote is registered by the server
                            send_count = 5  # Send 5 times to ensure it works
                            logging.info(f"[ENVIANDO AL SOCKET] Enviando paquete de emote {send_count} veces al socket Online...")
                            
                            for i in range(send_count):
                                socket_client.send(emote_packet)
                                logging.info(f"[ENVIADO] Paquete {i+1}/{send_count} enviado")
                                time.sleep(0.05)  # Small delay between sends
                            
                            logging.info(f"[OK] Todos los paquetes enviados exitosamente al socket")
                            
                            # Send a chat confirmation back to the user
                            clients.send(self.GenResponsMsg(f"[C][B][00FF00]EVO emote #{evo_choice} sent to {target_id}!", uid_sender))
                            logging.info(f"[CONFIRMACION] Mensaje de confirmacion enviado al usuario")
                        else:
                            logging.warning(f"[ERROR] IDs invalidos - Target: {target_id} (isdigit: {target_id.isdigit()}) | Emote: {emote_id} (isdigit: {emote_id.isdigit() if emote_id else False})")
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Invalid Player ID provided.", uid_sender))

                    except Exception as e:
                        # Consistent error handling with restart
                        logging.error(f"Error processing /evo command: {e}. Restarting.")
                        try:
                            # Attempt to notify the user about the error before restarting
                            json_result = get_available_room(data.hex()[10:])
                            parsed_data = json.loads(json_result)
                            uid = parsed_data["5"]["data"]["1"]["data"]
                            clients.send(self.GenResponsMsg("[C][B][FF0000]An error occurred. Restarting bot...", uid))
                        except:
                            pass 
                        restart_program()
#-------------------------------------------------------------#                                 
                if "1200" in data.hex()[0:4] and b'/play' in data:
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid_sender = parsed_data["5"]["data"]["1"]["data"]

                        # Command format: @a <target_id1> [target_id2...] <emote_id>
                        command_parts = data.split(b'/play')[1].split(b'(')[0].decode().strip().split()
                        if len(command_parts) < 2:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Usage: /play <target_id> <emote_id>", uid_sender))
                            continue

                        emote_id = command_parts[-1]
                        target_ids = command_parts[:-1]

                        clients.send(self.GenResponsMsg(f"[C][B][00FF00]Activating emote {emote_id} for {len(target_ids)} player(s)...", uid_sender))

                        # Verify socket is connected
                        try:
                            socket_client.getpeername()
                            logging.info(f"[SOCKET] Socket Online conectado correctamente para /play (ID directo)")
                        except Exception as e:
                            logging.error(f"[ERROR SOCKET] Socket no conectado: {e}")
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Error: Socket no conectado. El bot se reiniciará.", uid_sender))
                            restart_program()
                            continue

                        for target_id in target_ids:
                            if target_id.isdigit() and emote_id.isdigit():
                                logging.info(f"[CREANDO PAQUETE] Target: {target_id} | Emote ID: {emote_id}")
                                emote_packet = self.send_emote(target_id, emote_id)
                                
                                # Send the emote once and wait 5 seconds for it to complete
                                logging.info(f"[ENVIANDO] Enviando emote {emote_id} una vez y esperando 5 segundos...")
                                socket_client.send(emote_packet) # Send action to online socket
                                
                                # Wait 5 seconds for the emote animation to complete
                                time.sleep(5.0)
                                
                                logging.info(f"[OK] Emote {emote_id} completado (5 segundos) para {target_id}")
                        
                        clients.send(self.GenResponsMsg(f"[C][B][00FF00]Emote command completed!", uid_sender))

                    except Exception as e:
                        logging.error(f"Error processing /🙂play command: {e}")
                        try:
                            uid_sender = json.loads(get_available_room(data.hex()[10:]))["5"]["data"]["1"]["data"]
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Error processing /🙂play command.", uid_sender))
                        except:
                            pass                
#-------------------------------------------------------------#                                                
                if "1200" in data.hex()[0:4] and b'/nm' in data:
                    try:
                        logging.info(f"[COMANDO RECIBIDO] /nm detectado")
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid_sender = parsed_data["5"]["data"]["1"]["data"]
                        logging.info(f"[👤 USUARIO] UID del remitente: {uid_sender}")

                        # Command format: @b <target_id1> [target_id2...] <emote_id>
                        command_parts = data.split(b'/nm')[1].split(b'(')[0].decode().strip().split()
                        logging.info(f"[PARAMETROS] /nm con parametros: {command_parts}")
                        if len(command_parts) < 2:
                            logging.warning(f"[WARNING] /nm con parametros insuficientes. Enviando mensaje de uso.")
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Usage: /nm <target_id> <emote_id>", uid_sender))
                            continue

                        emote_id = command_parts[-1]
                        target_ids = command_parts[:-1]

                        clients.send(self.GenResponsMsg(f"[C][B][FF0000]ATTACKING with emote {emote_id} on {len(target_ids)} player(s)!", uid_sender))

                        # Loop for repeating the emote quickly
                        for _ in range(200): # Repeats 200 times
                            for target_id in target_ids:
                                if target_id.isdigit() and emote_id.isdigit():
                                    emote_packet = self.send_emote(target_id, emote_id)
                                    socket_client.send(emote_packet) # Send action to online socket
                            time.sleep(0.08) # Fast repeat speed

                        clients.send(self.GenResponsMsg(f"[C][B][00FF00]Emote attack finished!", uid_sender))

                    except Exception as e:
                        logging.error(f"Error processing /🙂nm command: {e}")
                        try:
                            uid_sender = json.loads(get_available_room(data.hex()[10:]))["5"]["data"]["1"]["data"]
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Error processing /🙂nm command.", uid_sender))
                        except:
                            pass                
#-------------------------------------------------------------#
                # COMANDOS ABREVIADOS - DETECCIÓN AUTOMÁTICA DE UID
                # /e <número> - Emote evolutiva (detecta UID automáticamente)
                if "1200" in data.hex()[0:4] and b"/e " in data and not b"/ev " in data and not b"/em " in data:
                    try:
                        logging.info(f"[COMANDO ABREVIADO] /e detectado")
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid_sender = parsed_data["5"]["data"]["1"]["data"]
                        # El UID objetivo es automáticamente el remitente
                        target_id = str(uid_sender)
                        
                        command_parts = data.split(b'/e ')[1].split(b'(')[0].decode().strip().split()
                        if not command_parts:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Usage: /e <número 1-17>\nEjemplo: /e 10", uid_sender))
                            continue
                        
                        evo_choice = command_parts[0]
                        evo_emotes = {
                            "1": "909000063", "2": "909000068", "3": "909000075", "4": "909040010",
                            "5": "909000081", "6": "909039011", "7": "909000085", "8": "909000090",
                            "9": "909000098", "10": "909035007", "11": "909042008", "12": "909041005",
                            "13": "909033001", "14": "909038010", "15": "909038012", "16": "909045001",
                            "17": "909049010"
                        }
                        emote_id = evo_emotes.get(evo_choice)
                        
                        if not emote_id:
                            clients.send(self.GenResponsMsg(f"[C][B][FF0000]Número inválido. Usa 1-17.\nEjemplo: /e 10", uid_sender))
                            continue
                        
                        try:
                            socket_client.getpeername()
                        except:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Error: Socket no conectado.", uid_sender))
                            continue
                        
                        emote_packet = self.send_emote(target_id, emote_id)
                        for i in range(5):
                            socket_client.send(emote_packet)
                            time.sleep(0.05)
                        
                        clients.send(self.GenResponsMsg(f"[C][B][00FF00]Emote evolutiva #{evo_choice} enviado!", uid_sender))
                        
                    except Exception as e:
                        logging.error(f"Error en /e: {e}")
#-------------------------------------------------------------#
                # /p <número> - Play emote (detecta UID automáticamente)
                if "1200" in data.hex()[0:4] and b"/p " in data and not b"/play " in data:
                    try:
                        logging.info(f"[COMANDO ABREVIADO] /p detectado")
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid_sender = parsed_data["5"]["data"]["1"]["data"]
                        target_id = str(uid_sender)
                        
                        command_parts = data.split(b'/p ')[1].split(b'(')[0].decode().strip().split()
                        if not command_parts:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Usage: /p <número>\nEjemplo: /p 50", uid_sender))
                            continue
                        
                        emote_choice = command_parts[0]
                        emote_map = {}
                        try:
                            with open('emotes.json', 'r') as f:
                                emotes_data = json.load(f)
                                for emote_entry in emotes_data:
                                    emote_map[emote_entry['Number']] = emote_entry['Id']
                        except:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Error: emotes.json no encontrado.", uid_sender))
                            continue
                        
                        if emote_choice not in emote_map:
                            max_num = len(emote_map)
                            clients.send(self.GenResponsMsg(f"[C][B][FF0000]Número inválido. Usa 1-{max_num}.", uid_sender))
                            continue
                        
                        emote_id_to_send = emote_map[emote_choice]
                        
                        try:
                            socket_client.getpeername()
                        except:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Error: Socket no conectado.", uid_sender))
                            continue
                        
                        emote_packet = self.send_emote(target_id, emote_id_to_send)
                        socket_client.send(emote_packet)
                        time.sleep(5.0)
                        
                        clients.send(self.GenResponsMsg(f"[C][B][00FF00]Emote #{emote_choice} completado!", uid_sender))
                        
                    except Exception as e:
                        logging.error(f"Error en /p: {e}")
#-------------------------------------------------------------#
                # /n <emote_id> - Spam emote (detecta UID automáticamente)
                if "1200" in data.hex()[0:4] and b"/n " in data and not b"/nm " in data:
                    try:
                        logging.info(f"[COMANDO ABREVIADO] /n detectado")
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid_sender = parsed_data["5"]["data"]["1"]["data"]
                        target_id = str(uid_sender)
                        
                        command_parts = data.split(b'/n ')[1].split(b'(')[0].decode().strip().split()
                        if not command_parts:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Usage: /n <emote_id>\nEjemplo: /n 909000063", uid_sender))
                            continue
                        
                        emote_id = command_parts[0]
                        
                        if not emote_id.isdigit():
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Emote ID debe ser numérico.", uid_sender))
                            continue
                        
                        try:
                            socket_client.getpeername()
                        except:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Error: Socket no conectado.", uid_sender))
                            continue
                        
                        clients.send(self.GenResponsMsg(f"[C][B][FF0000]Spam de emote iniciado!", uid_sender))
                        
                        for _ in range(200):
                            emote_packet = self.send_emote(target_id, emote_id)
                            socket_client.send(emote_packet)
                            time.sleep(0.08)
                        
                        clients.send(self.GenResponsMsg(f"[C][B][00FF00]Spam de emote completado!", uid_sender))
                        
                    except Exception as e:
                        logging.error(f"Error en /n: {e}")
#-------------------------------------------------------------#
                # /i [UID] - Invitar a squad (si no hay UID, invita al remitente)
                if "1200" in data.hex()[0:4]:
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    
                    # Extraer mensaje del campo 4 (donde está el texto del comando)
                    message_text = None
                    if "4" in parsed_data["5"]["data"] and "data" in parsed_data["5"]["data"]["4"]:
                        message_text = parsed_data["5"]["data"]["4"]["data"]
                    
                    if message_text and message_text.startswith("/i") and not message_text.startswith("/inv") and not message_text.startswith("/info"):
                        try:
                            logging.info(f"[COMANDO ABREVIADO] /i detectado: '{message_text}'")
                            uid_sender = parsed_data["5"]["data"]["1"]["data"]
                            
                            # Extraer parámetros si existen
                            match = re.search(r'/i\s+(\d+)', message_text)
                            if match:
                                command_parts = [match.group(1)]
                            else:
                                command_parts = []
                        
                            target_uid = command_parts[0] if command_parts and command_parts[0].isdigit() else str(uid_sender)
                            logging.info(f"[COMANDO /i] Target UID: {target_uid} | Sender: {uid_sender}")
                            
                            packetmaker = self.skwad_maker()
                            socket_client.send(packetmaker)
                            sleep(1)
                            packetfinal = self.changes(4)  # 5 jugadores
                            socket_client.send(packetfinal)
                            invitess = self.invite_skwad(target_uid)
                            socket_client.send(invitess)
                            invitessa = self.invite_skwad(str(uid_sender))
                            socket_client.send(invitessa)
                            clients.send(self.GenResponsMsg(f"[C][B][00ff00]Invitación enviada a {fix_num(target_uid)}!", uid_sender))
                            sleep(5)
                            leavee = self.leave_s()
                            socket_client.send(leavee)
                            sleep(1)
                            change_to_solo = self.changes(1)
                            socket_client.send(change_to_solo)
                            logging.info(f"[COMANDO /i] Completado exitosamente")
                        except Exception as e:
                            logging.error(f"Error en /i: {e}", exc_info=True)
#-------------------------------------------------------------#
                # /s [UID] - Spam de amistad (si no hay UID, spam al remitente)
                if "1200" in data.hex()[0:4] and b"/s " in data and not b"/spam " in data and not b"/sm " in data and not b"/solo" in data and not b"/start" in data and not b"/status" in data:
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid_sender = parsed_data["5"]["data"]["1"]["data"]
                        
                        command_parts = data.split(b'/s ')[1].split(b'(')[0].decode().strip().split()
                        target_uid = command_parts[0] if command_parts and command_parts[0].isdigit() else str(uid_sender)
                        
                        clients.send(self.GenResponsMsg(f"{generate_random_color()}Enviando solicitudes de amistad...", uid_sender))
                        message = send_spam(target_uid)
                        clients.send(self.GenResponsMsg(message, uid_sender))
                    except Exception as e:
                        logging.error(f"Error en /s: {e}")
#-------------------------------------------------------------#
                # /v [UID] - Visitas (si no hay UID, visitas al remitente)
                if "1200" in data.hex()[0:4]:
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    
                    # Extraer mensaje del campo 4
                    message_text = None
                    if "4" in parsed_data["5"]["data"] and "data" in parsed_data["5"]["data"]["4"]:
                        message_text = parsed_data["5"]["data"]["4"]["data"]
                    
                    if message_text and message_text.startswith("/v") and not message_text.startswith("/visit"):
                        try:
                            logging.info(f"[COMANDO ABREVIADO] /v detectado: '{message_text}'")
                            uid_sender = parsed_data["5"]["data"]["1"]["data"]
                            
                            match = re.search(r'/v\s+(\d+)', message_text)
                            if match:
                                command_parts = [match.group(1)]
                            else:
                                command_parts = []
                            
                            target_uid = command_parts[0] if command_parts and command_parts[0].isdigit() else str(uid_sender)
                            logging.info(f"[COMANDO /v] Target UID: {target_uid} | Sender: {uid_sender}")
                            
                            clients.send(self.GenResponsMsg(f"{generate_random_color()}Enviando 1000 visitas a {fix_num(target_uid)}...", uid_sender))
                            message = send_vistttt(target_uid)
                            logging.info(f"[COMANDO /v] Respuesta API: {message[:100] if message else 'None'}...")
                            clients.send(self.GenResponsMsg(message, uid_sender))
                        except Exception as e:
                            logging.error(f"Error en /v: {e}", exc_info=True)
#-------------------------------------------------------------#
                # /lk [UID] - Likes (si no hay UID, likes al remitente)
                if "1200" in data.hex()[0:4]:
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    
                    # Extraer mensaje del campo 4
                    message_text = None
                    if "4" in parsed_data["5"]["data"] and "data" in parsed_data["5"]["data"]["4"]:
                        message_text = parsed_data["5"]["data"]["4"]["data"]
                    
                    if message_text and message_text.startswith("/lk") and not message_text.startswith("/likes"):
                        try:
                            logging.info(f"[COMANDO ABREVIADO] /lk detectado: '{message_text}'")
                            uid_sender = parsed_data["5"]["data"]["1"]["data"]
                            
                            match = re.search(r'/lk\s+(\d+)', message_text)
                            if match:
                                command_parts = [match.group(1)]
                            else:
                                command_parts = []
                            
                            target_uid = command_parts[0] if command_parts and command_parts[0].isdigit() else str(uid_sender)
                            logging.info(f"[COMANDO /lk] Target UID: {target_uid} | Sender: {uid_sender}")
                            
                            clients.send(self.GenResponsMsg(f"{generate_random_color()}Procesando solicitud...", uid_sender))
                            likes_response = send_likes(target_uid)
                            logging.info(f"[COMANDO /lk] Respuesta API - Status: {likes_response.get('status')}")
                            if likes_response.get('status') == 'ok' or 'message' in likes_response:
                                clients.send(self.GenResponsMsg(likes_response['message'], uid_sender))
                            else:
                                clients.send(self.GenResponsMsg(f"[C][B][FF0000]Error: {likes_response.get('status', 'unknown')}", uid_sender))
                        except Exception as e:
                            logging.error(f"Error en /lk: {e}", exc_info=True)
#-------------------------------------------------------------#
                # /inf [UID] - Info (si no hay UID, info del remitente)
                if "1200" in data.hex()[0:4]:
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    
                    # Extraer mensaje del campo 4
                    message_text = None
                    if "4" in parsed_data["5"]["data"] and "data" in parsed_data["5"]["data"]["4"]:
                        message_text = parsed_data["5"]["data"]["4"]["data"]
                    
                    if message_text and message_text.startswith("/inf") and not message_text.startswith("/info"):
                        try:
                            logging.info(f"[COMANDO ABREVIADO] /inf detectado: '{message_text}'")
                            uid_sender = parsed_data["5"]["data"]["1"]["data"]
                            
                            match = re.search(r'/inf\s+(\d+)', message_text)
                            if match:
                                command_parts = [match.group(1)]
                            else:
                                command_parts = []
                            
                            target_uid = command_parts[0] if command_parts and command_parts[0].isdigit() else str(uid_sender)
                            logging.info(f"[COMANDO /inf] Target UID: {target_uid} | Sender: {uid_sender}")
                            
                            clients.send(self.GenResponsMsg(f"[C][B][FFFF00]Obteniendo info de {fix_num(target_uid)}...", uid_sender))
                            time.sleep(0.5)
                            info_response = newinfo(target_uid)
                            logging.info(f"[COMANDO /inf] Respuesta API - Status: {info_response.get('status')}")
                            
                            if info_response.get('status') != "ok":
                                clients.send(self.GenResponsMsg("[C][B][FF0000]Error al obtener info.", uid_sender))
                                continue
                            
                            info = info_response['info']
                            player_info_msg = (
                                f"[C][B][00FF00]━━「 Player Information 」━━\n"
                                f"[FFA500]• Name: [FFFFFF]{info.get('AccountName', 'N/A')}\n"
                                f"[FFA500]• Level: [FFFFFF]{info.get('AccountLevel', 'N/A')}\n"
                                f"[FFA500]• Likes: [FFFFFF]{fix_num(info.get('AccountLikes', 0))}\n"
                                f"[FFA500]• UID: [FFFFFF]{fix_num(info.get('accountId', 'N/A'))}\n"
                                f"[FFA500]• Region: [FFFFFF]{info.get('AccountRegion', 'N/A')}"
                            )
                            clients.send(self.GenResponsMsg(player_info_msg, uid_sender))
                            time.sleep(0.5)
                            
                            rank_info_msg = (
                                f"[C][B][00BFFF]━━「 Rank & Status 」━━\n"
                                f"[FFA500]• BR Rank: [FFFFFF]{info.get('BrMaxRank', 'N/A')} ({info.get('BrRankPoint', 0)} pts)\n"
                                f"[FFA500]• CS Rank: [FFFFFF]{info.get('CsMaxRank', 'N/A')} ({info.get('CsRankPoint', 0)} pts)\n"
                                f"[FFA500]• Bio: [FFFFFF]{info.get('signature', 'No Bio').replace('|', ' ')}"
                            )
                            clients.send(self.GenResponsMsg(rank_info_msg, uid_sender))
                            
                            if info.get('GuildID') and info.get('GuildID') != "0":
                                guild_info_msg = (
                                    f"[C][B][FFD700]━━「 Guild Information 」━━\n"
                                    f"[FFA500]• Name: [FFFFFF]{info.get('GuildName', 'N/A')}\n"
                                    f"[FFA500]• ID: [FFFFFF]{fix_num(info.get('GuildID', 'N/A'))}\n"
                                    f"[FFA500]• Members: [FFFFFF]{info.get('GuildMember', 0)}/{info.get('GuildCapacity', 0)}\n"
                                    f"[FFA500]• Level: [FFFFFF]{info.get('GuildLevel', 'N/A')}"
                                )
                                clients.send(self.GenResponsMsg(guild_info_msg, uid_sender))
                        except Exception as e:
                            logging.error(f"Error en /inf: {e}", exc_info=True)
#-------------------------------------------------------------#
                # /j <TeamCode> - Join (abreviado)
                if "1200" in data.hex()[0:4] and b"/j " in data and not b"/join " in data:
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid_sender = parsed_data["5"]["data"]["1"]["data"]
                        
                        command_parts = data.split(b'/j ')[1].split(b'(')[0].decode().strip().split()
                        if not command_parts:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Usage: /j <TeamCode>\nEjemplo: /j ABC123", uid_sender))
                            continue
                        
                        room_id = command_parts[0]
                        clients.send(self.GenResponsMsg(f"[C][B][32CD32]Uniéndose a sala: {room_id}", uid_sender))
                        join_teamcode(socket_client, room_id, key, iv)
                        time.sleep(0.1)
                        clients.send(self.GenResponsMsg(f"[C][B][00FF00]Unido exitosamente!", uid_sender))
                    except Exception as e:
                        logging.error(f"Error en /j: {e}")
#-------------------------------------------------------------#
                # /a <TeamCode> - Attack (abreviado)
                if "1200" in data.hex()[0:4] and b"/a " in data and not b"/attack " in data and not b"/admin " in data and not b"/ai " in data:
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid_sender = parsed_data["5"]["data"]["1"]["data"]
                        
                        command_parts = data.split(b'/a ')[1].split(b'(')[0].decode().strip().split()
                        if not command_parts:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Usage: /a <TeamCode>\nEjemplo: /a ABC123", uid_sender))
                            continue
                        
                        team_code = command_parts[0]
                        clients.send(self.GenResponsMsg(f"[C][B][FFA500]Ataque iniciado en {team_code}...", uid_sender))
                        start_packet = self.start_autooo()
                        leave_packet = self.leave_s()
                        attack_start_time = time.time()
                        while time.time() - attack_start_time < 45:
                            join_teamcode(socket_client, team_code, key, iv)
                            socket_client.send(start_packet)
                            socket_client.send(leave_packet)
                            time.sleep(0.15)
                        clients.send(self.GenResponsMsg(f"[C][B][00FF00]Ataque completado! ✅", uid_sender))
                    except Exception as e:
                        logging.error(f"Error en /a: {e}")
#-------------------------------------------------------------#
                # /t [UID] - Team spam (si no hay UID, spam al remitente)
                if "1200" in data.hex()[0:4] and b"/t " in data and not b"/team " in data:
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid_sender = parsed_data["5"]["data"]["1"]["data"]
                        
                        command_parts = data.split(b'/t ')[1].split(b'(')[0].decode().strip().split()
                        target_uid = command_parts[0] if command_parts and command_parts[0].isdigit() else str(uid_sender)
                        default_id = "2060437760"
                        team_uid = target_uid if target_uid.isdigit() else default_id
                        
                        clients.send(self.GenResponsMsg(f"[00FF00][b][c]SPAM DE TEAM INICIADO POR 10 SEGUNDOS EN: {fix_num(team_uid)}", uid_sender))
                        start_time = time.time()
                        while time.time() - start_time < 10:
                            packetmaker = self.skwad_maker()
                            socket_client.send(packetmaker)
                            sleep(0.05)
                            packetfinal_5 = self.changes(4)
                            socket_client.send(packetfinal_5)
                            invitess = self.invite_skwad(team_uid)
                            socket_client.send(invitess)
                            sleep(0.05)
                            packetfinal_6 = self.changes(5)
                            socket_client.send(packetfinal_6)
                        leavee = self.leave_s()
                        socket_client.send(leavee)
                        clients.send(self.GenResponsMsg(f"[00FF00][b][c]SPAM DE TEAM COMPLETADO!", uid_sender))
                    except Exception as e:
                        logging.error(f"Error en /t: {e}")
#-------------------------------------------------------------#
                if "1200" in data.hex()[0:4] and b"/start" in data:
                    try:
                        split_data = re.split(rb'/start', data)
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data['5']['data']['1']['data']
                        command_parts = split_data[1].split(b'(')[0].decode().strip().split()

                        if not command_parts:
                            clients.send(self.GenResponsMsg("[C][B][FF0000]Please provide a team code.", uid))
                            continue

                        team_code = command_parts[0]
                        spam_count = 20
                        if len(command_parts) > 1 and command_parts[1].isdigit():
                            spam_count = int(command_parts[1])
                        if spam_count > 50:
                            spam_count = 50

                        clients.send(
                            self.GenResponsMsg(f"[C][B][FFA500]Joining lobby to force start...", uid)
                        )
                        join_teamcode(socket_client, team_code, key, iv)
                        time.sleep(2)
                        clients.send(
                            self.GenResponsMsg(f"[C][B][FF0000]Spamming start command {spam_count} times!", uid)
                        )
                        start_packet = self.start_autooo()
                        for _ in range(spam_count):
                            socket_client.send(start_packet)
                            time.sleep(0.2)
                        leave_packet = self.leave_s()
                        socket_client.send(leave_packet)
                        clients.send(
                            self.GenResponsMsg(f"[C][B][00FF00]Force start process finished.", uid)
                        )
                    except Exception as e:
                        logging.error(f"An error occurred in /start command: {e}. Restarting.")
                        restart_program()
#-------------------------------------------------------------#                        
                if "1200" in data.hex()[0:4] and b"/snd" in data:
                    try:
                        i = re.split("/snd", str(data))[1]
                        if "***" in i:
                            i = i.replace("***", "106")
                        sid = str(i).split("(\\x")[0]
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        split_data = re.split(rb'/add', data)
                        room_data = split_data[1].split(b'(')[0].decode().strip().split()
                        if room_data:
                            iddd = room_data[0]
                            numsc1 = room_data[1] if len(room_data) > 1 else None

                            if numsc1 is None:
                                clients.send(
                                    self.GenResponsMsg(
                                        f"[C][B] [FF00FF]Please write id and count of the group\n[ffffff]Example : \n/snd 123[c]456[c]78 4\n/snd 123[c]456[c]78 5", uid
                                    )
                                )
                            else:
                                numsc = int(numsc1) - 1
                                if int(numsc1) < 3 or int(numsc1) > 6:
                                    clients.send(
                                        self.GenResponsMsg(
                                            f"[C][B][FF0000] Usage : /snd <uid> <Squad Type>\n[ffffff]Example : \n/add 12345678 4\n/add 12345678 5", uid
                                        )
                                    )
                                else:
                                    packetmaker = self.skwad_maker()
                                    socket_client.send(packetmaker)
                                    sleep(1)
                                    packetfinal = self.changes(int(numsc))
                                    socket_client.send(packetfinal)
                                    
                                    invitess = self.invite_skwad(iddd)
                                    socket_client.send(invitess)
                                    iddd1 = parsed_data["5"]["data"]["1"]["data"]
                                    invitessa = self.invite_skwad(iddd1)
                                    socket_client.send(invitessa)
                                    clients.send(
                                        self.GenResponsMsg(
                                            f"[C][B][00ff00]- Accept The Invite Quickly ! ", uid
                                        )
                                    )
                                    leaveee1 = True
                                    while leaveee1:
                                        if leaveee == True:
                                            #logging.info("Leave")
                                            leavee = self.leave_s()
                                            sleep(5)
                                            socket_client.send(leavee)   
                                            leaveee = False
                                            leaveee1 = False
                                            clients.send(
                                                self.GenResponsMsg(
                                                    f"[C][B] [FF00FF]success !", uid
                                                )
                                            )    
                                        if pleaseaccept == True:
                                            #logging.info("Leave")
                                            leavee = self.leave_s()
                                            socket_client.send(leavee)   
                                            leaveee1 = False
                                            pleaseaccept = False
                                            clients.send(
                                                self.GenResponsMsg(
                                                    f"[C][B] [FF00FF]Please accept the invite", uid
                                                )
                                            )   
                        else:
                            clients.send(
                                self.GenResponsMsg(
                                    f"[C][B] [FF00FF]Please write id and count of the group\n[ffffff]Example : \n/inv 123[c]456[c]78 4\n/inv 123[c]456[c]78 5", uid
                                )
                            )
                    except Exception as e:
                        logging.error(f"Error processing /🙂snd command: {e}. Restarting.")
                        restart_program()
            # --- START: Added for error handling ---
            except Exception as e:
                logging.critical(f"A critical unhandled error occurred in the main connect loop: {e}. The bot will restart.")
                restart_program()
            # --- END: Added for error handling ---

	                    
                    
    def parse_my_message(self, serialized_data):
        MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
        MajorLogRes.ParseFromString(serialized_data)
        
        timestamp = MajorLogRes.kts
        key = MajorLogRes.ak
        iv = MajorLogRes.aiv
        BASE64_TOKEN = MajorLogRes.token
        server_url = MajorLogRes.server_url  # Get URL from response
        timestamp_obj = Timestamp()
        timestamp_obj.FromNanoseconds(timestamp)
        timestamp_seconds = timestamp_obj.seconds
        timestamp_nanos = timestamp_obj.nanos
        combined_timestamp = timestamp_seconds * 1_000_000_000 + timestamp_nanos
        return combined_timestamp, key, iv, BASE64_TOKEN, server_url

    def GET_PAYLOAD_BY_DATA(self, JWT_TOKEN, NEW_ACCESS_TOKEN, date, base_url):
        logging.info("GET_PAYLOAD_BY_DATA called")
        token_payload_base64 = JWT_TOKEN.split('.')[1]
        token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
        decoded_payload = base64.urlsafe_b64decode(token_payload_base64).decode('utf-8')
        decoded_payload = json.loads(decoded_payload)
        NEW_EXTERNAL_ID = decoded_payload['external_id']
        SIGNATURE_MD5 = decoded_payload['signature_md5']
        now = datetime.now()
        now =str(now)[:len(str(now))-7]
        formatted_time = date
        payload = bytes.fromhex("1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131382e31422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033")
        payload = payload.replace(b"2025-07-30 11:02:51", str(now).encode())
        payload = payload.replace(b"ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a", NEW_ACCESS_TOKEN.encode("UTF-8"))
        payload = payload.replace(b"996a629dbcdb3964be6b6978f5d814db", NEW_EXTERNAL_ID.encode("UTF-8"))
        payload = payload.replace(b"7428b253defc164018c604a1ebbfebdf", SIGNATURE_MD5.encode("UTF-8"))
        PAYLOAD = payload.hex()
        PAYLOAD = encrypt_api(PAYLOAD)
        PAYLOAD = bytes.fromhex(PAYLOAD)
        logging.info("Calling GET_LOGIN_DATA from GET_PAYLOAD_BY_DATA")
        whisper_ip, whisper_port, online_ip, online_port = self.GET_LOGIN_DATA(JWT_TOKEN, PAYLOAD, base_url)
        if whisper_ip is None or online_ip is None:
            logging.error("GET_LOGIN_DATA returned None values")
            return None, None, None, None
        logging.info(f"GET_PAYLOAD_BY_DATA returning successfully: {whisper_ip}:{whisper_port}, {online_ip}:{online_port}")
        return whisper_ip, whisper_port, online_ip, online_port
    
    def dec_to_hex(ask):
        ask_result = hex(ask)
        final_result = str(ask_result)[2:]
        if len(final_result) == 1:
            final_result = "0" + final_result
            return final_result
        else:
            return final_result
    def convert_to_hex(PAYLOAD):
        hex_payload = ''.join([f'{byte:02x}' for byte in PAYLOAD])
        return hex_payload
    def convert_to_bytes(PAYLOAD):
        payload = bytes.fromhex(PAYLOAD)
        return payload
    def GET_LOGIN_DATA(self, JWT_TOKEN, PAYLOAD, base_url):
        global http_session
        logging.info(f"GET_LOGIN_DATA called with base_url: {base_url}")
        # Use dynamic URL from MajorLogin response (same as Guild-bot FUNCIONA)
        if not base_url or base_url.strip() == "":
            logging.error("Error: base_url está vacío o inválido")
            return None, None, None, None
        
        # Ensure URL has proper format
        if not base_url.startswith("http://") and not base_url.startswith("https://"):
            logging.error(f"Error: base_url no tiene protocolo (http/https): '{base_url}'")
            return None, None, None, None
        
        # Remove trailing slash to avoid double slash
        base_url = base_url.rstrip('/')
        url = f"{base_url}/GetLoginData"
        
        logging.info(f"Connecting to GetLoginData at: {url} (attempt will be logged)")
        
        headers = {
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Expect': '100-continue',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB51',
            'Authorization': f'Bearer {JWT_TOKEN}',
        }
        
        max_retries = 3
        attempt = 0

        while attempt < max_retries:
            try:
                response = http_session.post(url, headers=headers, data=PAYLOAD, verify=False, timeout=30)
                if response.status_code == 200:
                    # Process successful response
                    try:
                        x = response.content.hex()
                        json_result = get_available_room(x)
                        parsed_data = json.loads(json_result)
                        #logging.info(parsed_data)
                        
                        whisper_address = parsed_data['32']['data']
                        online_address = parsed_data['14']['data']
                        online_ip = online_address[:len(online_address) - 6]
                        whisper_ip = whisper_address[:len(whisper_address) - 6]
                        online_port = int(online_address[len(online_address) - 5:])
                        whisper_port = int(whisper_address[len(whisper_address) - 5:])
                        logging.info(f"Successfully obtained login data. Whisper: {whisper_ip}:{whisper_port}, Online: {online_ip}:{online_port}")
                        return whisper_ip, whisper_port, online_ip, online_port
                    except (KeyError, ValueError, IndexError, json.JSONDecodeError) as parse_error:
                        logging.error(f"Error parsing GetLoginData response: {parse_error}. Response content length: {len(response.content)}")
                        attempt += 1
                        if attempt < max_retries:
                            time.sleep(2)
                            continue
                        else:
                            logging.critical("Failed to parse login data after multiple attempts.")
                            return None, None, None, None
                else:
                    error_text = response.text[:200] if hasattr(response, 'text') else "No error text"
                    logging.error(f"GetLoginData failed with status {response.status_code}: {error_text}")
                    attempt += 1
                    if attempt < max_retries:
                        time.sleep(2)
                        continue
                    else:
                        logging.critical("Failed to get login data after multiple attempts.")
                        return None, None, None, None
            
            except requests.RequestException as e:
                logging.error(f"Request failed: {e}. Attempt {attempt + 1} of {max_retries}. Retrying...")
                attempt += 1
                if attempt < max_retries:
                    time.sleep(2)
                else:
                    logging.critical("Failed to get login data after multiple attempts.")
                    return None, None, None, None
            except Exception as e:
                logging.error(f"Unexpected error in GET_LOGIN_DATA: {e}. Attempt {attempt + 1} of {max_retries}")
                attempt += 1
                if attempt < max_retries:
                    time.sleep(2)
                else:
                    logging.critical("Failed to get login data after multiple attempts.")
                    return None, None, None, None

        return None, None, None, None

    def guest_token(self,uid , password):
        global http_session
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {"Host": "100067.connect.garena.com","User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 10;en;EN;)","Content-Type": "application/x-www-form-urlencoded","Accept-Encoding": "gzip, deflate, br","Connection": "close",}
        data = {"uid": f"{uid}","password": f"{password}","response_type": "token","client_type": "2","client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3","client_id": "100067",}
        response = http_session.post(url, headers=headers, data=data, timeout=30)
        if response.status_code != 200:
            logging.error(f"guest_token failed with status {response.status_code}")
            return False
        data = response.json()
        NEW_ACCESS_TOKEN = data.get('access_token')
        NEW_OPEN_ID = data.get('open_id')
        if not NEW_ACCESS_TOKEN or not NEW_OPEN_ID:
            logging.error("guest_token: Missing access_token or open_id in response")
            return False
        OLD_ACCESS_TOKEN = "ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a"
        OLD_OPEN_ID = "996a629dbcdb3964be6b6978f5d814db"
        time.sleep(0.2)
        token_data = self.TOKEN_MAKER(OLD_ACCESS_TOKEN , NEW_ACCESS_TOKEN , OLD_OPEN_ID , NEW_OPEN_ID,uid)
        if not token_data:
            logging.error("TOKEN_MAKER returned False")
            return False
        return token_data
        
    def TOKEN_MAKER(self,OLD_ACCESS_TOKEN , NEW_ACCESS_TOKEN , OLD_OPEN_ID , NEW_OPEN_ID,id):
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB51',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Content-Length': '928',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)',
            'Host': 'loginbp.ggblueshark.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        data = bytes.fromhex('1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131382e31422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033')
        data = data.replace(OLD_OPEN_ID.encode(),NEW_OPEN_ID.encode())
        data = data.replace(OLD_ACCESS_TOKEN.encode() , NEW_ACCESS_TOKEN.encode())
        hex = data.hex()
        d = encrypt_api(data.hex())
        Final_Payload = bytes.fromhex(d)
        URL = "https://loginbp.ggblueshark.com/MajorLogin"
        global http_session
        RESPONSE = http_session.post(URL, headers=headers, data=Final_Payload, verify=False, timeout=30)
        
        combined_timestamp, key, iv, BASE64_TOKEN, server_url = self.parse_my_message(RESPONSE.content)
        if RESPONSE.status_code == 200:
            if len(RESPONSE.text) < 10:
                logging.error("MajorLogin response too short")
                return False
            if not server_url or server_url.strip() == "":
                logging.error("Error: server_url está vacío en la respuesta de MajorLogin")
                return False
            logging.info(f"MajorLogin successful. Server URL: {server_url}")
            whisper_ip, whisper_port, online_ip, online_port = self.GET_PAYLOAD_BY_DATA(BASE64_TOKEN, NEW_ACCESS_TOKEN, 1, server_url)
            if whisper_ip is None or online_ip is None:
                logging.error("Failed to get login data from server")
                return False
            self.key = key
            self.iv = iv
            #logging.info(key, iv)
            return(BASE64_TOKEN, key, iv, combined_timestamp, whisper_ip, whisper_port, online_ip, online_port)
        else:
            return False
    
    def time_to_seconds(hours, minutes, seconds):
        return (hours * 3600) + (minutes * 60) + seconds

    def seconds_to_hex(seconds):
        return format(seconds, '04x')
    
    def extract_time_from_timestamp(timestamp):
        dt = datetime.fromtimestamp(timestamp)
        h = dt.hour
        m = dt.minute
        s = dt.second
        return h, m, s
    
    def get_tok(self):
        global g_token
        token_data = self.guest_token(self.id, self.password)
        if not token_data or token_data == False:
            logging.critical("Failed to get token data from guest_token. Restarting.")
            time.sleep(5)
            restart_program()
            return

        token, key, iv, Timestamp, whisper_ip, whisper_port, online_ip, online_port = token_data
        g_token = token
        #logging.info(f"{whisper_ip}, {whisper_port}")
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            account_id = decoded.get('account_id')
            encoded_acc = hex(account_id)[2:]
            hex_value = dec_to_hex(Timestamp)
            time_hex = hex_value
            BASE64_TOKEN_ = token.encode().hex()
            logging.info(f"Token decoded and processed. Account ID: {account_id}")
        except Exception as e:
            logging.error(f"Error processing token: {e}. Restarting.")
            restart_program()

        try:
            head = hex(len(encrypt_packet(BASE64_TOKEN_, key, iv)) // 2)[2:]
            length = len(encoded_acc)
            zeros = '00000000'

            if length == 9:
                zeros = '0000000'
            elif length == 8:
                zeros = '00000000'
            elif length == 10:
                zeros = '000000'
            elif length == 7:
                zeros = '000000000'
            else:
                logging.warning('Unexpected length encountered')
            head = f'0115{zeros}{encoded_acc}{time_hex}00000{head}'
            final_token = head + encrypt_packet(BASE64_TOKEN_, key, iv)
            logging.info("Final token constructed successfully.")
        except Exception as e:
            logging.error(f"Error constructing final token: {e}. Restarting.")
            restart_program()
        token = final_token
        self.connect(token, 'anything', key, iv, whisper_ip, whisper_port, online_ip, online_port)
        
      
        return token, key, iv
        
with open('Nm.txt', 'r') as file:
    data = json.load(file)
ids_passwords = list(data.items())
def run_client(id, password):
    logging.info(f"Starting client for ID: {id}")
    client = FF_CLIENT(id, password)
    # Guardar instancia para uso del panel web
    set_active_client(client)
    # The start method is inherited from threading.Thread and calls the run() method
    # The logic is handled within the FF_CLIENT class itself upon instantiation.
    # No need to call client.start() as it's not defined to do anything special here.
    
max_range = 300000
num_clients = len(ids_passwords)
num_threads = 1
start = 0
end = max_range
step = (end - start) // num_threads
threads = []

# --- START: HTTP Server for Panel Integration ---
import http.server
import socketserver
from urllib.parse import urlparse, parse_qs
import json as json_module

# Variable global para almacenar la instancia del cliente activo
active_client_instance = None

# Variable global para rastrear si el servidor HTTP ya está iniciado
panel_server_started = False
panel_server_thread = None

def set_active_client(client):
    """Establece la instancia del cliente activo para uso del panel"""
    global active_client_instance
    active_client_instance = client
    logging.info(f"[PANEL] Cliente activo establecido: {client.id if hasattr(client, 'id') else 'N/A'}")

def process_panel_command(command, uid, emote_number, category=None, command_type='/play'):
    """
    Procesa un comando del panel web usando la MISMA lógica que el procesamiento del chat.
    Esto simula que el comando viene del chat del juego.
    Comando esperado: /play [UID] [Number] o /ev [UID] [Number] para evolutivas
    También procesa: /join [teamcode] y /solo
    category: "evolutivas", "normales", "duo" - determina qué mapeo usar
    command_type: "/ev" o "/play" - determina qué comando usar
    """
    global active_client_instance, socket_client, clients
    
    try:
        logging.info(f"[PANEL] Comando recibido del panel: {command} | UID: {uid} | Emote: {emote_number} | Categoría: {category}")
        logging.info(f"[PANEL] Simulando procesamiento como si viniera del chat del juego")
        logging.info(f"[PANEL] active_client_instance: {active_client_instance}")
        
        # Verificar que las variables globales existan antes de hacer logging
        try:
            socket_client_val = socket_client if 'socket_client' in globals() else None
            logging.info(f"[PANEL] socket_client: {socket_client_val}")
        except NameError:
            logging.warning("[PANEL] socket_client no está definido aún")
            socket_client_val = None
        
        try:
            clients_val = clients if 'clients' in globals() else None
            logging.info(f"[PANEL] clients: {clients_val}")
        except NameError:
            logging.warning("[PANEL] clients no está definido aún")
            clients_val = None
        
        if not active_client_instance:
            logging.error("[PANEL] No hay instancia de cliente activa - Intentando encontrar cliente activo...")
            # Intentar establecer el cliente si no está establecido
            if 'client' in globals():
                set_active_client(globals()['client'])
                logging.info("[PANEL] Cliente encontrado y establecido")
            else:
                return {"success": False, "message": "Bot no conectado. Espera a que el bot se conecte completamente."}
        
        # ============================================
        # VERIFICAR SI ES COMANDO DE EQUIPO (/join o /solo) ANTES DE PROCESAR COMO EMOTE
        # ============================================
        if command.startswith('/join'):
            logging.info(f"[PANEL] Detectado como comando /join (unirse a equipo)")
            try:
                # Extraer el código de equipo del comando (igual que en el chat)
                command_parts = command.split()
                if len(command_parts) < 2:
                    return {"success": False, "message": "Please provide a room code."}
                
                room_id = command_parts[1]
                logging.info(f"[PANEL] Intentando unirse al equipo: {room_id}")
                
                # Verificar que socket_client esté conectado
                try:
                    if 'socket_client' not in globals() or socket_client is None:
                        return {"success": False, "message": "Error: Socket no inicializado."}
                    socket_client.getpeername()
                except Exception as e:
                    return {"success": False, "message": f"Error: Socket no conectado. {str(e)}"}
                
                # Obtener key e iv de la instancia del cliente (igual que en el chat)
                key = active_client_instance.key
                iv = active_client_instance.iv
                
                if not key or not iv:
                    return {"success": False, "message": "Error: Key/IV no inicializados. Espera a que el bot se conecte completamente."}
                
                # Ejecutar join_teamcode (IGUAL QUE EN EL CHAT - línea 2742)
                # join_teamcode ya está importado con "from byte import*" al inicio del archivo
                join_teamcode(socket_client, room_id, key, iv)
                
                # SIN PAUSA - ejecución inmediata
                
                logging.info(f"[PANEL] ✅ Unido al equipo {room_id} exitosamente")
                return {
                    "success": True,
                    "message": f"Successfully joined the room: {room_id}"
                }
                
            except Exception as e:
                logging.error(f"[PANEL] Error processing /join command: {e}", exc_info=True)
                return {"success": False, "message": f"An error occurred during /join: {str(e)}"}
        
        elif command == '/solo':
            logging.info(f"[PANEL] Detectado como comando /solo (salir del equipo)")
            try:
                # Verificar que socket_client esté conectado
                try:
                    if 'socket_client' not in globals() or socket_client is None:
                        return {"success": False, "message": "Error: Socket no inicializado."}
                    socket_client.getpeername()
                except Exception as e:
                    return {"success": False, "message": f"Error: Socket no conectado. {str(e)}"}
                
                # Ejecutar leave_s y changes(1) (IGUAL QUE EN EL CHAT - líneas 2805-2809)
                leavee = active_client_instance.leave_s()
                socket_client.send(leavee)
                # SIN PAUSA - ejecución inmediata
                change_to_solo = active_client_instance.changes(1)
                socket_client.send(change_to_solo)
                
                logging.info(f"[PANEL] ✅ Salido del equipo exitosamente")
                return {
                    "success": True,
                    "message": "Exited from the group."
                }
                
            except Exception as e:
                logging.error(f"[PANEL] Error processing /solo command: {e}", exc_info=True)
                return {"success": False, "message": f"An error occurred during /solo: {str(e)}"}
        
        # ============================================
        # SI NO ES /join NI /solo, PROCESAR COMO EMOTE
        # ============================================
        
        # --- START: Determinar qué mapeo usar ---
        emote_id_to_send = None
        
        # Si es una evolutiva (comando /ev o categoría evolutivas), usar el mapeo de /ev
        if command_type == '/ev' or category == "evolutivas" or (emote_number.isdigit() and 1 <= int(emote_number) <= 17 and category == "evolutivas"):
            logging.info(f"[PANEL] Detectado como emote evolutiva, usando mapeo de /ev (como comando /ev del chat)")
            evo_emotes = {
                "1": "909000063",   # AK
                "2": "909000068",   # SCAR
                "3": "909000075",   # 1st MP40
                "4": "909040010",   # 2nd MP40
                "5": "909000081",   # 1st M1014
                "6": "909039011",   # 2nd M1014
                "7": "909000085",   # XM8
                "8": "909000090",   # Famas
                "9": "909000098",   # UMP
                "10": "909035007",  # M1887
                "11": "909042008",  # Woodpecker
                "12": "909041005",  # Groza
                "13": "909033001",  # M4A1
                "14": "909038010",  # Thompson
                "15": "909038012",  # G18
                "16": "909045001",  # Parafal
                "17": "909049010"   # P90
            }
            emote_id_to_send = evo_emotes.get(emote_number)
            
            if not emote_id_to_send:
                return {"success": False, "message": f"Invalid evolutiva number. Please use a number from 1-17."}
            
            logging.info(f"[PANEL] Mapeo evolutiva: {emote_number} -> {emote_id_to_send}")
        else:
            # Para normales y dúo, usar emotes.json (como /play)
            logging.info(f"[PANEL] Detectado como emote normal/dúo, usando emotes.json")
            emote_map = {}
            try:
                with open('emotes.json', 'r') as f:
                    emotes_data = json.load(f)
                    for emote_entry in emotes_data:
                        emote_map[emote_entry['Number']] = emote_entry['Id']
            except FileNotFoundError:
                logging.error("[PANEL] CRITICAL: emotes.json file not found!")
                return {"success": False, "message": "Error: emotes.json file is missing. Please contact the admin."}
            except (json.JSONDecodeError, KeyError):
                logging.error("[PANEL] CRITICAL: emotes.json is formatted incorrectly!")
                return {"success": False, "message": "Error: Emote data file is corrupted. Please contact the admin."}
            
            if emote_number not in emote_map:
                max_emote_number = len(emote_map)
                return {"success": False, "message": f"Invalid emote number. Please use a number between 1 and {max_emote_number}."}
            
            emote_id_to_send = emote_map[emote_number]
            logging.info(f"[PANEL] Mapeo normal/dúo: {emote_number} -> {emote_id_to_send}")
        # --- END: Determinar qué mapeo usar ---
        
        # Parse the command parts (simulando como si viniera del chat)
        target_ids = [uid]
        emote_choice = emote_number
        
        # Enviar mensaje de confirmación (como lo hace el chat)
        # En el chat usa: clients.send(self.GenResponsMsg(...))
        # Para el panel, solo logueamos pero no enviamos mensaje al chat
        logging.info(f"[PANEL] Sending emote #{emote_choice} to {len(target_ids)} player(s)...")
        
        # Verify socket is connected (MISMA VERIFICACIÓN QUE EL CHAT)
        try:
            # Verificar que socket_client existe y está conectado
            if 'socket_client' not in globals() or socket_client is None:
                logging.error("[PANEL] socket_client no está definido")
                return {"success": False, "message": "Error: Socket no inicializado. Espera a que el bot se conecte completamente."}
            
            socket_client.getpeername()
            logging.info(f"[PANEL] Socket Online conectado correctamente para /play")
        except AttributeError:
            logging.error("[PANEL] socket_client no tiene el método getpeername - no está conectado")
            return {"success": False, "message": "Error: Socket no conectado. Espera a que el bot se conecte completamente."}
        except Exception as e:
            logging.error(f"[PANEL] ERROR SOCKET - Socket no conectado: {e}")
            return {"success": False, "message": f"Error: Socket no conectado. {str(e)}"}
        
        # Loop through all provided target IDs (MISMA LÓGICA QUE EL CHAT)
        for target_id in target_ids:
            if target_id.isdigit() and emote_id_to_send.isdigit():
                logging.info(f"[PANEL] CREANDO PAQUETE - Target: {target_id} | Emote ID: {emote_id_to_send} (número: {emote_choice})")
                emote_packet = active_client_instance.send_emote(target_id, emote_id_to_send)
                
                # Para evolutivas (comando /ev), usar el mismo método que /ev (5 veces con delay)
                # Para normales/dúo (comando /play), usar el método de /play (1 vez y esperar 5 segundos)
                if command_type == '/ev' or category == "evolutivas":
                    logging.info(f"[PANEL] ENVIANDO EVOLUTIVA (/ev) - Enviando emote #{emote_choice} 5 veces (como /ev del chat)...")
                    for i in range(5):
                        socket_client.send(emote_packet)
                        logging.info(f"[PANEL] Paquete {i+1}/5 enviado")
                        # SIN PAUSA entre envíos - ejecución inmediata
                    logging.info(f"[PANEL] OK - Emote evolutiva #{emote_choice} enviado a {target_id}")
                else:
                    # Send the emote once (sin espera)
                    logging.info(f"[PANEL] ENVIANDO - Enviando emote #{emote_choice} una vez...")
                    socket_client.send(emote_packet)
                    
                    # SIN PAUSA - ejecución inmediata
                    
                    logging.info(f"[PANEL] OK - Emote #{emote_choice} enviado a {target_id}")
        
        # Mensaje de éxito (como lo hace el chat)
        logging.info(f"[PANEL] Emote #{emote_choice} completed successfully!")
        return {
            "success": True, 
            "message": f"Emote #{emote_choice} completed successfully!"
        }
            
    except Exception as e:
        logging.error(f"[PANEL] Error processing /play command: {e}", exc_info=True)
        return {"success": False, "message": f"An error occurred with /play: {str(e)}"}

class PanelHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Manejador de requests HTTP para el panel web"""
    
    def do_OPTIONS(self):
        """Manejar preflight CORS"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, ngrok-skip-browser-warning')
        self.end_headers()
    
    def do_GET(self):
        """Manejar GET requests - para verificar estado"""
        if self.path == '/api/status':
            try:
                global active_client_instance, socket_client, clients
                
                status = {
                    "active_client": active_client_instance is not None,
                    "client_id": active_client_instance.id if active_client_instance and hasattr(active_client_instance, 'id') else None,
                    "socket_connected": False,
                    "clients_connected": False
                }
                
                # Verificar socket_client
                try:
                    if 'socket_client' in globals() and socket_client is not None:
                        socket_client.getpeername()
                        status["socket_connected"] = True
                except:
                    pass
                
                # Verificar clients
                try:
                    if 'clients' in globals() and clients is not None:
                        clients.getpeername()
                        status["clients_connected"] = True
                except:
                    pass
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json_module.dumps(status).encode('utf-8'))
            except Exception as e:
                logging.error(f"[PANEL] Error en GET /api/status: {e}")
                self.send_response(500)
                self.end_headers()
        elif self.path == '/health' or self.path == '/':
            # Health check endpoint para Railway (mantiene el servicio activo)
            try:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                health_response = {
                    "status": "ok",
                    "service": "david-ia-bot",
                    "timestamp": time.time(),
                    "uptime": time.time() - bot_start_time if 'bot_start_time' in globals() else 0
                }
                self.wfile.write(json_module.dumps(health_response).encode('utf-8'))
                logging.info(f"[HEALTH] Health check recibido - Servicio activo")
            except Exception as e:
                logging.error(f"[HEALTH] Error en health check: {e}")
                self.send_response(500)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        """Manejar POST requests del panel"""
        if self.path == '/api/send-command':
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                data = json_module.loads(post_data.decode('utf-8'))
                
                command = data.get('command', '')
                uid = data.get('uid', '')
                emote_number = data.get('emote_number', '')
                category = data.get('category', None)  # "evolutivas", "normales", "duo"
                command_type = data.get('command_type', '/play')  # "/ev" o "/play"
                
                logging.info(f"[PANEL] Request recibido: command={command}, uid={uid}, emote_number={emote_number}, category={category}, command_type={command_type}")
                
                # Procesar el comando
                result = process_panel_command(command, uid, emote_number, category, command_type)
                
                # Enviar respuesta
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json_module.dumps(result).encode('utf-8'))
                
            except Exception as e:
                logging.error(f"[PANEL] Error en POST: {e}", exc_info=True)
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json_module.dumps({
                    "success": False,
                    "message": f"Error del servidor: {str(e)}"
                }).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        """Suprimir logs de HTTP server (ya tenemos logging propio)"""
        pass

def iniciar_servidor_http():
    """
    Arranca el servidor HTTP para el panel en el thread principal.
    Usa el puerto dinámico de Railway.
    IMPORTANTE: Esta función debe correr en el thread principal, NO en un daemon thread.
    """
    global panel_server_started
    
    # Leer puerto de variable de entorno PORT (Railway lo asigna automáticamente)
    # IMPORTANTE: Railway asigna el puerto dinámicamente, este default es solo para desarrollo local
    port = int(os.environ.get('PORT', 8080))
    logging.info(f"[PANEL] Iniciando servidor HTTP en puerto {port}")
    
    try:
        # Crear servidor con SO_REUSEADDR para permitir reutilización del puerto
        class ReusableTCPServer(socketserver.TCPServer):
            allow_reuse_address = True
        
        httpd = ReusableTCPServer(("0.0.0.0", port), PanelHTTPRequestHandler)
        
        logging.info(f"[PANEL] Servidor HTTP iniciado en puerto {port}")
        logging.info(f"[PANEL] Panel web puede conectarse a: https://web-production-ddaf8.up.railway.app/api/send-command")
        logging.info(f"[PANEL] Health check disponible en: https://web-production-ddaf8.up.railway.app/health")
        panel_server_started = True
        
        # Iniciar keep-alive loop en un thread daemon separado
        try:
            start_keep_alive_loop()
        except Exception as e:
            logging.warning(f"[KEEP-ALIVE] No se pudo iniciar keep-alive: {e}")
        
        # serve_forever() bloquea el thread principal - esto es correcto
        # Railway necesita que el proceso principal esté activo
        httpd.serve_forever()
        
    except OSError as e:
        error_str = str(e)
        if "10048" in error_str or "address already in use" in error_str.lower() or "10060" in error_str:
            logging.error(f"[PANEL] Puerto {port} ya está en uso. No se puede iniciar el servidor HTTP.")
            logging.error(f"[PANEL] Esto puede causar que el bot no responda a requests del panel.")
            raise
        else:
            logging.error(f"[PANEL] Error iniciando servidor HTTP en puerto {port}: {e}")
            raise
    except Exception as e:
        logging.error(f"[PANEL] Error inesperado iniciando servidor HTTP: {e}")
        raise

def start_keep_alive_loop():
    """Envía requests HTTP periódicos para mantener el servicio activo en Railway"""
    import urllib.request
    
    def keep_alive():
        while True:
            try:
                time.sleep(60)  # Cada 60 segundos (1 minuto)
                # Hacer un request a nuestro propio health check
                try:
                    port = int(os.environ.get('PORT', 8080))
                    url = f"http://localhost:{port}/health"
                    urllib.request.urlopen(url, timeout=5)
                    logging.debug("[KEEP-ALIVE] Health check interno enviado")
                except Exception as e:
                    logging.debug(f"[KEEP-ALIVE] Error en keep-alive interno: {e}")
            except Exception as e:
                logging.error(f"[KEEP-ALIVE] Error en loop de keep-alive: {e}")
                time.sleep(60)
    
    keep_alive_thread = threading.Thread(target=keep_alive, daemon=True)
    keep_alive_thread.start()
    logging.info("[KEEP-ALIVE] Keep-alive loop iniciado")
    return keep_alive_thread
# --- END: HTTP Server for Panel Integration ---

# --- START: Modified for robust execution and restart ---
if __name__ == "__main__":
    # Prevenir múltiples instancias usando un lock file
    lock_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.bot_lock')
    
    # Verificar si ya hay una instancia corriendo
    if os.path.exists(lock_file):
        try:
            # Leer el PID del archivo lock
            with open(lock_file, 'r') as f:
                old_pid = int(f.read().strip())
            
            # Verificar si el proceso todavía está corriendo
            try:
                process = psutil.Process(old_pid)
                if process.is_running():
                    logging.warning(f"[INIT] Ya hay una instancia del bot corriendo (PID: {old_pid})")
                    logging.warning("[INIT] Cerrando esta instancia para evitar conflictos...")
                    sys.exit(0)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # El proceso ya no existe, eliminar el lock file
                try:
                    os.remove(lock_file)
                except:
                    pass
        except Exception as e:
            logging.warning(f"[INIT] Error verificando lock file: {e}")
            # Si hay error, eliminar el lock file y continuar
            try:
                os.remove(lock_file)
            except:
                pass
    
    # Crear el lock file con el PID actual
    try:
        with open(lock_file, 'w') as f:
            f.write(str(os.getpid()))
    except Exception as e:
        logging.warning(f"[INIT] No se pudo crear lock file: {e}")
    
    # Función para limpiar el lock file al salir
    def cleanup_lock():
        try:
            if os.path.exists(lock_file):
                os.remove(lock_file)
        except:
            pass
    
    import atexit
    atexit.register(cleanup_lock)
    
    # Initialize persistent HTTP session for connection pooling
    http_session = requests.Session()
    http_session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    # Configure connection pooling
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=20,
        pool_maxsize=20,
        max_retries=3
    )
    http_session.mount('http://', adapter)
    http_session.mount('https://', adapter)
    logging.info("HTTP session initialized with connection pooling.")
    
    def iniciar_bot():
        """
        Función principal del bot que se ejecuta en un thread daemon.
        Si crashea, NO cierra el proceso principal (el servidor HTTP sigue funcionando).
        """
        try:
            logging.info("[BOT] Iniciando bot en thread daemon...")
            
            while True:  # Loop de reinicio del bot
                try:
                    logging.info("[BOT] Main execution block started.")
                    # Your original threading logic
                    for i in range(num_threads):
                        ids_for_thread = ids_passwords[i % num_clients]
                        id_val, password_val = ids_for_thread
                        # The FF_CLIENT init starts the connection logic, which is run in a new thread inside the connect method.
                        # The primary thread for each client is created inside its `connect` method.
                        # This main thread's purpose is to kick off the clients.
                        run_client(id_val, password_val)
                        time.sleep(3)  # Stagger client startups

                    # Keep the main script alive by joining the threads that were created.
                    # The threads list is populated inside the connect method.
                    logging.info(f"[BOT] All {len(threads)} client threads initiated. Main thread will now wait.")
                    for thread in threads:
                        thread.join()

                except KeyboardInterrupt:
                    logging.info("[BOT] Shutdown signal received. Exiting bot thread.")
                    if http_session:
                        http_session.close()
                    break
                except Exception as e:
                    logging.critical(f"[BOT] A critical error occurred in the main execution block: {e}")
                    logging.error(f"[BOT] Error details: {type(e).__name__}: {str(e)}")
                    import traceback
                    logging.error(f"[BOT] Traceback: {traceback.format_exc()}")
                    
                    # En lugar de reiniciar inmediatamente, esperar más tiempo
                    logging.info("[BOT] Esperando 10 segundos antes de reintentar...")
                    if http_session:
                        try:
                            http_session.close()
                        except:
                            pass
                    time.sleep(10)
                    # Continuar el loop para reintentar (NO usar restart_program aquí)
                    logging.info("[BOT] Reintentando conexión...")
                    
        except Exception as e:
            logging.critical(f"[BOT] Error fatal en thread del bot: {e}")
            # NO llamar a restart_program() - dejar que el thread termine
            # El servidor HTTP seguirá funcionando
    
    # 1) Bot corriendo en un hilo daemon en segundo plano
    # Si el bot crashea, NO cierra el proceso principal
    hilo_bot = threading.Thread(target=iniciar_bot, daemon=True)
    hilo_bot.start()
    logging.info("[MAIN] Bot iniciado en thread daemon")
    
    # 2) Servidor HTTP en el hilo principal
    # Este bloquea el thread principal con serve_forever()
    # Railway necesita que el proceso principal esté activo
    try:
        iniciar_servidor_http()
    except Exception as e:
        logging.critical(f"[MAIN] Error fatal iniciando servidor HTTP: {e}")
        logging.critical(f"[MAIN] El bot no puede funcionar sin el servidor HTTP. Saliendo...")
        cleanup_lock()
        sys.exit(1)
