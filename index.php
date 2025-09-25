<?php
class OrderKuotaReport {
    const BASE_URL = 'https://report.orderkuota.com';
    const LOGIN_URL = 'https://report.orderkuota.com/login';
    const MUTASI_URL = 'https://report.orderkuota.com/mutasi_qris';
    
    private $email;
    private $password;
    private $cookieFile;
    private $userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36';

    public function __construct($email, $password) {
        $this->email = $email;
        $this->password = $password;
        $this->cookieFile = tempnam(sys_get_temp_dir(), 'orderkuota_cookie');
    }

    public function __destruct() {
        if (file_exists($this->cookieFile)) {
            unlink($this->cookieFile);
        }
    }

    public function login() {
        // First, get CSRF token from login page
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => self::LOGIN_URL,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_COOKIEJAR => $this->cookieFile,
            CURLOPT_COOKIEFILE => $this->cookieFile,
            CURLOPT_USERAGENT => $this->userAgent,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_TIMEOUT => 30
        ]);

        $html = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        if ($httpCode !== 200) {
            curl_close($ch);
            return [
                'status' => false,
                'message' => 'Failed to access login page',
                'http_code' => $httpCode
            ];
        }

        // Extract CSRF token
        $csrfToken = $this->extractCSRFToken($html);
        
        if (!$csrfToken) {
            curl_close($ch);
            return [
                'status' => false,
                'message' => 'Failed to extract CSRF token'
            ];
        }

        // Prepare login data
        $postData = http_build_query([
            'email' => $this->email,
            'password' => $this->password,
            '_token' => $csrfToken
        ]);

        // Perform login
        curl_setopt_array($ch, [
            CURLOPT_URL => self::LOGIN_URL,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $postData,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/x-www-form-urlencoded',
                'Referer: ' . self::LOGIN_URL
            ]
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $redirectUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        curl_close($ch);

        // Check if login was successful (usually redirects to dashboard)
        if ($httpCode === 200 && strpos($redirectUrl, 'dashboard') !== false) {
            return [
                'status' => true,
                'message' => 'Login successful'
            ];
        }

        return [
            'status' => false,
            'message' => 'Login failed - invalid credentials or server error',
            'http_code' => $httpCode
        ];
    }

    public function getMutasiQris($filterPencairan = true) {
        // Check if we have valid cookies (logged in)
        if (!file_exists($this->cookieFile) || filesize($this->cookieFile) === 0) {
            $loginResult = $this->login();
            if (!$loginResult['status']) {
                return $loginResult;
            }
        }

        // Get mutasi data
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => self::MUTASI_URL,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_COOKIEFILE => $this->cookieFile,
            CURLOPT_COOKIEJAR => $this->cookieFile,
            CURLOPT_USERAGENT => $this->userAgent,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_HTTPHEADER => [
                'Referer: ' . self::BASE_URL . '/dashboard'
            ]
        ]);

        $html = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200) {
            return [
                'status' => false,
                'message' => 'Failed to fetch mutasi data',
                'http_code' => $httpCode
            ];
        }

        // Parse the HTML to extract transaction data
        $transactions = $this->parseMutasiHTML($html, $filterPencairan);

        return [
            'status' => true,
            'message' => 'Data fetched successfully',
            'data' => $transactions,
            'total_transactions' => count($transactions)
        ];
    }

    private function extractCSRFToken($html) {
        // Look for CSRF token in meta tag
        if (preg_match('/<meta name="csrf-token" content="([^"]+)"/', $html, $matches)) {
            return $matches[1];
        }
        
        // Look for CSRF token in input field
        if (preg_match('/<input[^>]*name="_token"[^>]*value="([^"]+)"/', $html, $matches)) {
            return $matches[1];
        }

        return null;
    }

    private function parseMutasiHTML($html, $filterPencairan = true) {
        $transactions = [];
        
        // Remove extra spaces and newlines for easier parsing
        $html = preg_replace('/\s+/', ' ', $html);
        
        // Pattern to match transaction blocks
        // This pattern looks for date-time pattern followed by transaction details
        $pattern = '/(\d{2}\/\d{2}\/\d{4} \d{2}:\d{2})<\/td>\s*<td[^>]*>([^<]+)<\/td>\s*<td[^>]*>([^<]*)<\/td>\s*<td[^>]*>([^<]*)<\/td>\s*<td[^>]*>([^<]*)<\/td>/i';
        
        preg_match_all($pattern, $html, $matches, PREG_SET_ORDER);
        
        foreach ($matches as $match) {
            $dateTime = trim($match[1]);
            $description = trim($match[2]);
            $nominal = trim($match[3]);
            $potongan = trim($match[4]);
            $total = trim($match[5]);
            
            // Skip withdrawal transactions if filtering is enabled
            if ($filterPencairan && stripos($description, 'pencairan saldo qris') !== false) {
                continue;
            }
            
            // Clean up nominal values (remove non-numeric characters except dots and commas)
            $nominal = preg_replace('/[^\d.,]/', '', $nominal);
            $total = preg_replace('/[^\d.,]/', '', $total);
            
            $transaction = [
                'tanggal' => $dateTime,
                'deskripsi' => $description,
                'nominal' => $nominal,
                'potongan' => $potongan,
                'total' => $total,
                'tipe' => stripos($description, 'pencairan') !== false ? 'OUT' : 'IN'
            ];
            
            $transactions[] = $transaction;
        }
        
        // Alternative parsing method if the above doesn't work
        if (empty($transactions)) {
            $transactions = $this->parseAlternativeMethod($html, $filterPencairan);
        }
        
        return $transactions;
    }

    private function parseAlternativeMethod($html, $filterPencairan) {
        $transactions = [];
        
        // Split by table rows
        $rows = explode('</tr>', $html);
        
        foreach ($rows as $row) {
            if (strpos($row, '<td') === false) continue;
            
            // Extract all table cells
            preg_match_all('/<td[^>]*>(.*?)<\/td>/', $row, $cells);
            
            if (count($cells[1]) >= 5) {
                $dateTime = trim(strip_tags($cells[1][0]));
                $description = trim(strip_tags($cells[1][1]));
                $nominal = trim(strip_tags($cells[1][2]));
                $potongan = trim(strip_tags($cells[1][3]));
                $total = trim(strip_tags($cells[1][4]));
                
                // Validate date format
                if (!preg_match('/\d{2}\/\d{2}\/\d{4} \d{2}:\d{2}/', $dateTime)) {
                    continue;
                }
                
                // Skip withdrawal transactions if filtering is enabled
                if ($filterPencairan && stripos($description, 'pencairan saldo qris') !== false) {
                    continue;
                }
                
                $transaction = [
                    'tanggal' => $dateTime,
                    'deskripsi' => $description,
                    'nominal' => $nominal,
                    'potongan' => $potongan,
                    'total' => $total,
                    'tipe' => stripos($description, 'pencairan') !== false ? 'OUT' : 'IN'
                ];
                
                $transactions[] = $transaction;
            }
        }
        
        return $transactions;
    }
}

// API Handler
if (isset($_GET['action'])) {
    header('Content-Type: application/json');
    
    $response = [
        'status' => false,
        'message' => 'Unknown error',
        'timestamp' => time()
    ];
    
    try {
        switch ($_GET['action']) {
            case 'mutasiqris':
                if (!isset($_POST['email']) || !isset($_POST['password'])) {
                    $response['message'] = 'Email and password are required';
                    break;
                }
                
                $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
                $password = $_POST['password'];
                
                if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                    $response['message'] = 'Invalid email format';
                    break;
                }
                
                $report = new OrderKuotaReport($email, $password);
                $result = $report->getMutasiQris(true); // true = filter out withdrawals
                
                if ($result['status']) {
                    $response = $result;
                    $response['message'] = 'Mutasi data retrieved successfully';
                } else {
                    $response['message'] = $result['message'];
                    if (isset($result['http_code'])) {
                        $response['http_code'] = $result['http_code'];
                    }
                }
                break;
                
            default:
                $response['message'] = 'Unknown action';
        }
    } catch (Exception $e) {
        $response['message'] = 'Server error: ' . $e->getMessage();
    }
    
    echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}
?>
