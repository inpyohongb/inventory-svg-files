import os
import sys
import json
import time
import gzip
import threading
import hashlib
import urllib.parse
import webbrowser
import requests
from io import BytesIO
from datetime import datetime
from functools import lru_cache, wraps
from collections import defaultdict

import pytz
from flask import Flask, render_template, send_file, jsonify, request, Response, redirect, session, url_for
from jinja2 import Template as JinjaTemplate
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# Electron/PyInstaller 패키징 시 리소스 경로 설정
def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fallback_secret_key')

# 앱 버전 정보
APP_VERSION = "1.0.0"  # 코드 변경 시 이 버전을 증가시켜야 함
APP_UPDATE_CHECK_URL = "https://inpyohongb.github.io/inventory-svg-files/app_version.json"
APP_DOWNLOAD_URL = "https://inpyohongb.github.io/inventory-svg-files/app/"

# SVG 버전 관리를 위한 설정
SVG_REPOSITORY_URL = "https://inpyohongb.github.io/inventory-svg-files/svg"
SVG_LOCAL_DIR = os.path.join(os.path.expanduser("~"), ".inventory_viewer", "svg")
VERSION_CHECK_URL = "https://inpyohongb.github.io/inventory-svg-files/version.json"

# 템플릿 파일 동적 로드를 위한 설정 (기존 version.json 사용)
TEMPLATE_REPOSITORY_URL = "https://inpyohongb.github.io/inventory-svg-files/templates"
TEMPLATE_LOCAL_DIR = os.path.join(os.path.expanduser("~"), ".inventory_viewer", "templates")
# 템플릿도 루트의 version.json에서 확인 (SVG와 동일)

# Configuration
SCOPES = ['https://www.googleapis.com/auth/spreadsheets.readonly']
CLIENT_SECRET_FILE = resource_path('./client_secret.json')  # OAuth 2.0 클라이언트 ID JSON
# 토큰은 번들 내부가 아닌 사용자 홈 디렉터리에 저장합니다 (PyInstaller 번들 호환)
TOKEN_DIR = os.path.join(os.path.expanduser("~"), ".inventory_viewer")
os.makedirs(TOKEN_DIR, exist_ok=True)
TOKEN_FILE = os.path.join(TOKEN_DIR, 'token.json')  # 액세스 토큰 저장 파일 (사용자 홈)
SAMPLE_SPREADSHEET_ID = '1-cVxZ3xxbXmrsqdxKRisXlwyXlYMptMXUhaPlXg3nwM'
PICKING_RANGE_NAME = 'goods!A1:W'
REPLENISHMENT_RANGE_NAME = 'goods2!A1:V'
ID_RANGE_NAME = 'ID!A2:A'
SKU_TREND_RANGE_NAME = 'picking_sku!A1:U' 
UNIT_TREND_RANGE_NAME = 'picking_unit!A1:U'

# 템플릿 파일 관리 클래스 (SVG와 유사한 구조)
class TemplateManager:
    def __init__(self):
        # 로컬 템플릿 디렉토리 생성
        if not os.path.exists(TEMPLATE_LOCAL_DIR):
            os.makedirs(TEMPLATE_LOCAL_DIR, exist_ok=True)
        
        self.template_files = {}  # 파일명: 해시값
        self.load_local_template_info()
    
    def load_local_template_info(self):
        info_path = os.path.join(TEMPLATE_LOCAL_DIR, "template_info.json")
        if os.path.exists(info_path):
            with open(info_path, 'r') as f:
                self.template_files = json.load(f)
    
    def save_local_template_info(self):
        info_path = os.path.join(TEMPLATE_LOCAL_DIR, "template_info.json")
        with open(info_path, 'w') as f:
            json.dump(self.template_files, f)
    
    def check_for_updates(self):
        """서버에서 템플릿 파일 업데이트 확인 및 다운로드 (루트 version.json 사용)"""
        try:
            response = requests.get(VERSION_CHECK_URL, headers={'Cache-Control': 'no-cache'}, timeout=10)
            
            if response.status_code == 200:
                all_files = response.json()
                # 템플릿 파일만 필터링 (templates/ 접두사가 있는 파일)
                remote_files = {}
                for key, value in all_files.items():
                    if key.startswith('templates/'):
                        # templates/index.html -> index.html로 변환
                        filename = key.replace('templates/', '')
                        remote_files[filename] = value
                
                if not remote_files:
                    return False
        
                # 각 파일 확인
                for filename, remote_hash in remote_files.items():
                    local_file_path = os.path.join(TEMPLATE_LOCAL_DIR, filename)
                
                    # 로컬 파일이 존재하는지 확인
                    file_exists = os.path.exists(local_file_path)
                    update_needed = True
                
                    if file_exists:
                        # 파일이 있으면 현재 해시 계산 (SHA256 사용, SVG와 동일)
                        with open(local_file_path, 'rb') as f:
                            content = f.read()
                            current_hash = hashlib.sha256(content).hexdigest()
                    
                        # 해시 비교로 업데이트 필요성 결정
                        update_needed = current_hash != remote_hash
                
                    # 파일이 없거나 해시가 다른 경우 다운로드
                    if not file_exists or update_needed:
                        result = self._download_template(filename)
                        if result:
                            self.template_files[filename] = remote_hash
        
                self.save_local_template_info()
                return True
            return False
        except Exception as e:
            return False
    
    def _download_template(self, filename):
        """템플릿 파일 다운로드"""
        try:
            file_url = f"{TEMPLATE_REPOSITORY_URL}/{filename}"
            response = requests.get(file_url, timeout=30)
        
            if response.status_code == 200:
                local_path = os.path.join(TEMPLATE_LOCAL_DIR, filename)
                with open(local_path, 'wb') as f:
                    f.write(response.content)
                return True
            else:
                return False
        except Exception as e:
            return False
    
    def get_template_path(self, filename):
        """템플릿 파일의 로컬 경로 반환, 없으면 기본 경로 반환"""
        local_path = os.path.join(TEMPLATE_LOCAL_DIR, filename)
        if os.path.exists(local_path):
            return local_path
        # 로컬에 없으면 기본 템플릿 경로 반환 (오프라인 대비)
        return resource_path(f'templates/{filename}')

# SVG 파일 관리 클래스
class SvgManager:
    def __init__(self):
        # 로컬 SVG 디렉토리 생성
        if not os.path.exists(SVG_LOCAL_DIR):
            os.makedirs(SVG_LOCAL_DIR, exist_ok=True)
        
        self.svg_files = {}  # 파일명: 해시값
        self.load_local_svg_info()
    
    def load_local_svg_info(self):
        info_path = os.path.join(SVG_LOCAL_DIR, "svg_info.json")
        if os.path.exists(info_path):
            with open(info_path, 'r') as f:
                self.svg_files = json.load(f)
    
    def save_local_svg_info(self):
        info_path = os.path.join(SVG_LOCAL_DIR, "svg_info.json")
        with open(info_path, 'w') as f:
            json.dump(self.svg_files, f)
    
    def check_for_updates(self):
        """서버에서 SVG 파일 업데이트 확인 및 다운로드"""
        try:
            response = requests.get(VERSION_CHECK_URL, headers={'Cache-Control': 'no-cache'})
    
            if response.status_code == 200:
                remote_files = response.json()
                # filter out template files and non-svg files to avoid unnecessary 404 downloads
                filtered_files = {}
                for key, value in remote_files.items():
                    # skip template files
                    if key.startswith('templates/'):
                        continue
                    # ensure only svg files are processed
                    if not key.lower().endswith('.svg'):
                        continue
                    # normalize filename by removing svg/ prefix if present
                    filename = key.replace('svg/', '') if key.startswith('svg/') else key
                    filtered_files[filename] = value
                if not filtered_files:
                    return False
        
                # 각 파일 확인
                for filename, remote_hash in filtered_files.items():
                    local_file_path = os.path.join(SVG_LOCAL_DIR, filename)
                
                    # 로컬 파일이 존재하는지 확인
                    file_exists = os.path.exists(local_file_path)
                    update_needed = True
                
                    if file_exists:
                        # 파일이 있으면 현재 해시 계산
                        with open(local_file_path, 'rb') as f:
                            content = f.read()
                            current_hash = hashlib.md5(content).hexdigest()
                    
                        # 해시 비교로 업데이트 필요성 결정
                        update_needed = current_hash != remote_hash
                
                    # 파일이 없거나 해시가 다른 경우 다운로드
                    if not file_exists or update_needed:
                        result = self._download_svg(filename)
                        if result:
                            self.svg_files[filename] = remote_hash
        
                self.save_local_svg_info()
                return True
            return False
        except Exception as e:
            return False
    
    def _download_svg(self, filename):
        """SVG 파일 다운로드"""
        try:
            file_url = f"{SVG_REPOSITORY_URL}/{filename}"
            response = requests.get(file_url)
        
            if response.status_code == 200:
                local_path = os.path.join(SVG_LOCAL_DIR, filename)
                # create subdirectories if any (e.g., nested folders) before saving
                local_dir = os.path.dirname(local_path)
                if local_dir and not os.path.exists(local_dir):
                    os.makedirs(local_dir, exist_ok=True)
                with open(local_path, 'wb') as f:
                    f.write(response.content)
                return True
            else:
                return False
        except Exception as e:
            return False
    
    def get_svg_path(self, filename):
        """SVG 파일의 로컬 경로 반환"""
        return os.path.join(SVG_LOCAL_DIR, filename)

class Cache:
    def __init__(self):
        self.data = defaultdict(list)
        self.serialized_data = defaultdict(str)  # 직렬화된 데이터 저장
        self.filtered_cache = defaultdict(dict)  # 필터링된 결과 캐시
        self.last_update = defaultdict(str)
        self.lock = threading.Lock()
        self._sheet_service = None

    @property
    def sheet_service(self):
        if self._sheet_service is None:
            creds = self._get_credentials()
            self._sheet_service = build('sheets', 'v4', credentials=creds)
        return self._sheet_service
    
    def _get_credentials(self):
        """OAuth 2.0 인증 - 사용자 인증 사용"""
        creds = None
        
        # 저장된 토큰이 있으면 로드
        if os.path.exists(TOKEN_FILE):
            creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
        
        # 토큰이 없거나 만료되었으면 새로 인증
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                # 첫 인증 시 브라우저 창 열림 (사용자가 회사 이메일로 로그인)
                flow = InstalledAppFlow.from_client_secrets_file(
                    CLIENT_SECRET_FILE, SCOPES)
                creds = flow.run_local_server(port=0)
            
            # 토큰 저장 (다음 실행 시 재사용)
            with open(TOKEN_FILE, 'w') as token:
                token.write(creds.to_json())
        
        return creds

    def get_data(self, data_type):
        with self.lock:
            return self.serialized_data[data_type], self.last_update[data_type]

    def update_data(self, data_type, new_data, update_time):
        with self.lock:
            self.data[data_type] = new_data
            self.last_update[data_type] = update_time
            # 데이터를 미리 직렬화하여 저장
            self.serialized_data[data_type] = json.dumps({
                'data': new_data,
                'lastUpdateTime': update_time
            }, ensure_ascii=False)
            # 필터 캐시 초기화
            self.filtered_cache[data_type].clear()

    def get_filtered_data(self, data_type, filters):
        """필터링된 데이터를 캐시하고 반환"""
        filter_key = str(sorted(filters.items()))
        
        with self.lock:
            # 캐시된 결과가 있으면 반환
            if filter_key in self.filtered_cache[data_type]:
                return self.filtered_cache[data_type][filter_key]
            
            # 필터링 수행
            filtered_data = [
                item for item in self.data[data_type]
                if all(item.get(k) == v for k, v in filters.items())
            ]
            
            # 결과 직렬화 및 캐시
            result = json.dumps({
                'data': filtered_data,
                'lastUpdateTime': self.last_update[data_type]
            }, ensure_ascii=False)
            
            self.filtered_cache[data_type][filter_key] = result
            return result

# 캐시 초기화
cache = Cache()
svg_manager = SvgManager()
template_manager = TemplateManager()

def compress_response(minimum_size=1000):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            response = f(*args, **kwargs)
            
            if not isinstance(response, Response):
                return response
            
            accept_encoding = request.headers.get('Accept-Encoding', '')
            if 'gzip' not in accept_encoding.lower():
                return response
            
            response_data = response.get_data()
            
            if len(response_data) < minimum_size:
                return response
            
            gzip_buffer = BytesIO()
            with gzip.GzipFile(mode='wb', fileobj=gzip_buffer, compresslevel=4) as gz:
                gz.write(response_data)
            
            compressed_response = Response(gzip_buffer.getvalue())
            compressed_response.headers['Content-Encoding'] = 'gzip'
            compressed_response.headers['Content-Length'] = len(compressed_response.get_data())
            compressed_response.headers['Vary'] = 'Accept-Encoding'
            
            for key, value in response.headers.items():
                if key not in ('Content-Encoding', 'Content-Length', 'Vary'):
                    compressed_response.headers[key] = value
            
            return compressed_response
        return wrapped
    return decorator

def fetch_sheet_data(range_name):
    try:
        result = cache.sheet_service.spreadsheets().values().get(
            spreadsheetId=SAMPLE_SPREADSHEET_ID,
            range=range_name
        ).execute()
        
        values = result.get('values', [])
        
        if not values:
            # 한국 시간으로 변환
            kst = pytz.timezone('Asia/Seoul')
            now = datetime.now(pytz.UTC).astimezone(kst)
            return [], now.strftime("%Y-%m-%d %H:%M:%S")

        if range_name == ID_RANGE_NAME:
            kst = pytz.timezone('Asia/Seoul')
            now = datetime.now(pytz.UTC).astimezone(kst)
            result_data = [row[0] for row in values if row]
            return result_data, now.strftime("%Y-%m-%d %H:%M:%S")

        headers = values[0]
        data = [
            {headers[i]: row[i] for i in range(len(headers)) if i < len(row)}
            for row in values[1:]
        ]
        
        kst = pytz.timezone('Asia/Seoul')
        now = datetime.now(pytz.UTC).astimezone(kst)
        return data, now.strftime("%Y-%m-%d %H:%M:%S")
    
    except Exception as e:
        kst = pytz.timezone('Asia/Seoul')
        now = datetime.now(pytz.UTC).astimezone(kst)
        return [], now.strftime("%Y-%m-%d %H:%M:%S")

def update_cache():
    # SVG 파일 업데이트 확인
    svg_manager.check_for_updates()
    # 템플릿 파일 업데이트 확인
    template_manager.check_for_updates()
    
    while True:
        try:
            data_types = {
                'picking': PICKING_RANGE_NAME,
                'replenishment': REPLENISHMENT_RANGE_NAME,
                'valid_ids': ID_RANGE_NAME,
                'sku_trend': SKU_TREND_RANGE_NAME,
                'unit_trend': UNIT_TREND_RANGE_NAME
            }
            
            for data_type, range_name in data_types.items():
                data, update_time = fetch_sheet_data(range_name)
                cache.update_data(data_type, data, update_time)
            
            # 10분마다 데이터 업데이트
            time.sleep(600)
            
            # 한 시간마다 SVG 및 템플릿 업데이트 확인
            if time.time() % 3600 < 600:
                svg_manager.check_for_updates()
                template_manager.check_for_updates()
                
        except Exception as e:
            print(f"Error in cache update: {e}")
            time.sleep(60)

# 라우트 핸들러 (일부 수정)
@app.route('/get_svg/<sheet>')
def get_svg(sheet):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # 로컬 SVG 파일 경로 사용
    svg_path = svg_manager.get_svg_path(f"{sheet}.svg")
    
    if not os.path.exists(svg_path):
        return jsonify({"error": "SVG file not found"}), 404
    
    try:
        # 파일 내용 확인
        with open(svg_path, 'r', encoding='utf-8') as f:
            content = f.read()
            if not content.strip().startswith('<'):
                return Response("SVG 파일 형식이 잘못되었습니다.", status=500)
        
        response = send_file(
            svg_path,
            mimetype='image/svg+xml'
        )
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        # 파일 수정 시간을 ETag로 활용
        response.headers['ETag'] = str(os.path.getmtime(svg_path))
        return response
    except Exception as e:
        return Response(f"SVG 파일 로딩 중 오류 발생: {e}", status=500)

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # 동적 템플릿 로드 시도, 실패하면 기본 템플릿 사용
    template_path = template_manager.get_template_path('index.html')
    try:
        # Flask 앱 컨텍스트에서 템플릿 렌더링 (url_for 등 지원)
        from flask import render_template_string
        with open(template_path, 'r', encoding='utf-8') as f:
            template_content = f.read()
        # Jinja2 템플릿으로 렌더링하여 url_for 등 Flask 함수 사용 가능
        return render_template_string(template_content)
    except Exception as e:
        return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id = request.form['user_id']
        valid_ids, _ = cache.get_data('valid_ids')
        if user_id in valid_ids:
            session['user_id'] = user_id
            return redirect(url_for('index'))
        # 동적 템플릿 로드 시도
        template_path = template_manager.get_template_path('login.html')
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                template_content = f.read()
            # Jinja2 템플릿 변수 처리
            template = JinjaTemplate(template_content)
            rendered = template.render(error=True)
            return Response(rendered, mimetype='text/html')
        except Exception as e:
            return render_template('login.html', error=True)
    # 동적 템플릿 로드 시도
    template_path = template_manager.get_template_path('login.html')
    try:
        with open(template_path, 'r', encoding='utf-8') as f:
            template_content = f.read()
        # Jinja2 템플릿 변수 처리
        template = JinjaTemplate(template_content)
        rendered = template.render(error=False)
        return Response(rendered, mimetype='text/html')
    except Exception as e:
        return render_template('login.html', error=False)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/api/inventory_data')
@compress_response(minimum_size=1000)
def get_inventory_data():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    sheet = request.args.get('sheet', '2F(피킹)')
    data_type = 'picking' if '피킹' in sheet else 'replenishment'
    
    # 필터 파라미터 처리
    filters = {
        k: v for k, v in request.args.items() 
        if k != 'sheet'
    }
    
    # 필터가 없는 경우 미리 직렬화된 데이터 반환
    if not filters:
        response_data, _ = cache.get_data(data_type)
    else:
        # 필터링된 데이터 캐시에서 가져오기
        response_data = cache.get_filtered_data(data_type, filters)
    
    response = Response(
        response_data,
        content_type='application/json; charset=utf-8'
    )
    response.headers['Cache-Control'] = 'public, max-age=60'
    return response


@app.route('/api/zone_statistics')
@compress_response(minimum_size=500)
def get_zone_statistics():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    # Summary 탭 전용 엔드포인트: 항상 goods 시트(picking 데이터)만 사용
    data = cache.data.get('picking', [])

    def parse_number_py(v):
        if v is None:
            return 0.0
        if isinstance(v, (int, float)):
            return float(v)
        s = str(v).replace(',', '').strip()
        # remove non-numeric except dot and minus
        import re
        s = re.sub(r"[^0-9.\-]", '', s)
        try:
            return float(s) if s != '' else 0.0
        except:
            return 0.0

    zones = {}
    for item in data:
        zone = (item.get('존') or item.get('ZONE') or item.get('zone') or '').strip() or '미지정'
        if zone not in zones:
            zones[zone] = {'avgSalesSum': 0.0, 'skuSet': set(), 'unitSum': 0.0, 'categoryCounts': {}}

        z = zones[zone]
        z['avgSalesSum'] += parse_number_py(item.get('평균판매량') or item.get('평균 판매량') or item.get('L') or 0)
        code = item.get('상품코드') or item.get('상품 코드') or item.get('goodsCode') or item.get('A') or ''
        if code:
            z['skuSet'].add(str(code))
        z['unitSum'] += parse_number_py(item.get('재고') or item.get('K') or 0)
        cat = (item.get('카테고리') or item.get('category') or item.get('G') or '').strip() or '미분류'
        z['categoryCounts'][cat] = z['categoryCounts'].get(cat, 0) + 1

    # convert sets to counts and format
    result = {}
    for zone, info in zones.items():
        result[zone] = {
            'avgSalesSum': round(info['avgSalesSum'], 2),
            'SKU': len(info['skuSet']),
            'UNIT': round(info['unitSum'], 2),
            'categoryCounts': info['categoryCounts']
        }

    # include last update times for visibility
    last_picking = cache.last_update.get('picking', '')
    last_replenishment = cache.last_update.get('replenishment', '')

    return jsonify({'zone_statistics': result, 'lastUpdate': {'picking': last_picking, 'replenishment': last_replenishment}})


@app.route('/api/sku_trend')
def get_sku_trend():
    """피킹SKU 시트 데이터를 조회하는 엔드포인트
    
    반환 형식:
    {
        'dates': ['2024-01-01', '2024-01-02', ...],
        'zones': {
            '2FA': [100, 105, 110, ...],  # 각 날짜별 SKU 수
            '2FM': [95, 98, 102, ...],
            ...
        },
        'lastUpdate': '2024-01-15 14:30:00'
    }
    """
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        # 피킹SKU 시트 데이터 가져오기
        sku_trend_data, update_time = cache.get_data('sku_trend')
        
        if isinstance(sku_trend_data, str):
            # JSON 문자열인 경우 파싱
            sku_trend_data = json.loads(sku_trend_data)
            sku_trend_data = sku_trend_data.get('data', [])
        
        if not sku_trend_data:
            return jsonify({'dates': [], 'zones': {}, 'lastUpdate': update_time})
        
        # 데이터는 이미 딕셔너리 형식이고, 첫 번째 행도 데이터이다
        # 각 행: {'date': '2025-07-11', '2FA': '28', '2FM': '3', ...}
        
        dates = []
        zones_data = {}
        
        # 모든 존 이름 수집 (첫 번째 row를 기록으로 사용하여 존 이름 추출)
        first_row = sku_trend_data[0]
        if isinstance(first_row, dict):
            # 'date' 키를 제외한 모든 키가 존 이름
            zone_names = [k for k in first_row.keys() if k != 'date' and k.upper() != 'TOTAL']
            for zone in zone_names:
                zones_data[zone] = []
        
        # 각 행 처리
        for row_idx, row in enumerate(sku_trend_data):
            if isinstance(row, dict):
                # 날짜 추출
                date = row.get('date', '')
                if date:
                    dates.append(str(date))
                    
                    # 각 존의 SKU 수 추출
                    for zone in zone_names:
                        value = row.get(zone, 0)
                        # 숫자로 변환 (콤마 제거)
                        try:
                            # 문자열에서 콤마 제거
                            str_value = str(value).replace(',', '').strip() if value else '0'
                            num_value = int(float(str_value)) if str_value else 0
                            zones_data[zone].append(num_value)
                        except (ValueError, TypeError) as e:
                            zones_data[zone].append(0)
        
        result = {
            'dates': dates,
            'zones': zones_data,
            'lastUpdate': update_time
        }
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/unit_trend')
def get_unit_trend():
    """피킹UNIT 시트 데이터를 조회하는 엔드포인트
    반환 형식은 /api/sku_trend와 동일하게 반환합니다.
    """
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        unit_trend_data, update_time = cache.get_data('unit_trend')

        if isinstance(unit_trend_data, str):
            unit_trend_data = json.loads(unit_trend_data)
            unit_trend_data = unit_trend_data.get('data', [])

        if not unit_trend_data:
            return jsonify({'dates': [], 'zones': {}, 'lastUpdate': update_time})

        dates = []
        zones_data = {}

        first_row = unit_trend_data[0]
        if isinstance(first_row, dict):
            zone_names = [k for k in first_row.keys() if k != 'date' and k.upper() != 'TOTAL']
            for zone in zone_names:
                zones_data[zone] = []

        for row in unit_trend_data:
            if isinstance(row, dict):
                date = row.get('date', '')
                if date:
                    dates.append(str(date))
                    for zone in zone_names:
                        value = row.get(zone, 0)
                        try:
                            str_value = str(value).replace(',', '').strip() if value else '0'
                            num_value = int(float(str_value)) if str_value else 0
                            zones_data[zone].append(num_value)
                        except (ValueError, TypeError):
                            zones_data[zone].append(0)

        result = {
            'dates': dates,
            'zones': zones_data,
            'lastUpdate': update_time
        }

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500





def start_browser():
    """앱 실행 시 브라우저 자동 실행"""
    time.sleep(1.5)  # 서버가 시작될 때까지 잠시 대기
    webbrowser.open('http://localhost:5000')

def initialize_cache():
    """서버 시작 시 초기 데이터 로드 및 통계 계산"""
    try:
        data, update_time = fetch_sheet_data(PICKING_RANGE_NAME)
        cache.update_data('picking', data, update_time)
        
        replenishment_data, replenishment_time = fetch_sheet_data(REPLENISHMENT_RANGE_NAME)
        cache.update_data('replenishment', replenishment_data, replenishment_time)
        
        id_data, id_time = fetch_sheet_data(ID_RANGE_NAME)
        cache.update_data('valid_ids', id_data, id_time)
        
        sku_trend_data, sku_trend_time = fetch_sheet_data(SKU_TREND_RANGE_NAME)
        cache.update_data('sku_trend', sku_trend_data, sku_trend_time)
        # UNIT 트렌드 데이터(picking_unit)도 함께 로드
        unit_trend_data, unit_trend_time = fetch_sheet_data(UNIT_TREND_RANGE_NAME)
        cache.update_data('unit_trend', unit_trend_data, unit_trend_time)
    except Exception as e:
        pass

if __name__ == '__main__':
    # SVG 디렉토리 초기화
    if os.path.exists(SVG_LOCAL_DIR):
        for file in os.listdir(SVG_LOCAL_DIR):
            file_path = os.path.join(SVG_LOCAL_DIR, file)
            if os.path.isfile(file_path):
                os.unlink(file_path)
    # SVG 및 템플릿 업데이트 체크
    svg_manager.check_for_updates()
    template_manager.check_for_updates()
    
    # 초기 데이터 로드 및 통계 계산
    initialize_cache()
    
    # 백그라운드 스레드로 캐시 업데이트
    threading.Thread(target=update_cache, daemon=True).start()
    
    # 브라우저 자동 실행
    threading.Thread(target=start_browser, daemon=True).start()
    
    # 로컬 서버 실행
    app.run(host='127.0.0.1', port=5000, debug=False)