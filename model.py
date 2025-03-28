import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import re
from datetime import  datetime
from urllib.parse import urlparse
import joblib
import tldextract
from security_checks import SecurityChecker

class URLDetector:
    def __init__(self):
        self.classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.security_checker = SecurityChecker()
        self.features_list = [
            'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens',
            'nb_at', 'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore',
            'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star', 'nb_colon',
            'nb_comma', 'nb_semicolumn', 'nb_dollar', 'nb_space', 'nb_www',
            'nb_com', 'nb_dslash', 'http_in_path', 'https_token',
            'ratio_digits_url', 'ratio_digits_host', 'punycode',
            'port', 'tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain',
            'nb_subdomains', 'prefix_suffix', 'random_domain',
            'shortening_service', 'path_extension',
            'has_ssl', 'ssl_valid', 'dns_consistency',
            'domain_age_days', 'suspicious_ip_reputation',
            'has_dns_records', 'has_reverse_dns',
            'suspicious_registration'
        ]
        self.trusted_domains = {
            'usertesting.com', 'abuseipdb.com', 'google.com', 'microsoft.com',
            'github.com', 'amazonaws.com', 'adobe.com', 'apple.com'
        }
    
    def extract_features(self, url):
        try:
            features = {}
            parsed = urlparse(url)
            extract = tldextract.extract(url)
            domain = parsed.netloc
            path = parsed.path

            # Basic length features
            features['length_url'] = len(url)
            features['length_hostname'] = len(domain)

            # IP address check
            features['ip'] = 1 if re.match(
                r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', domain
            ) else 0

            # Count various characters
            features['nb_dots'] = url.count('.')
            features['nb_hyphens'] = url.count('-')
            features['nb_at'] = url.count('@')
            features['nb_qm'] = url.count('?')
            features['nb_and'] = url.count('&')
            features['nb_or'] = url.count('|')
            features['nb_eq'] = url.count('=')
            features['nb_underscore'] = url.count('_')
            features['nb_tilde'] = url.count('~')
            features['nb_percent'] = url.count('%')
            features['nb_slash'] = url.count('/')
            features['nb_star'] = url.count('*')
            features['nb_colon'] = url.count(':')
            features['nb_comma'] = url.count(',')
            features['nb_semicolumn'] = url.count(';')
            features['nb_dollar'] = url.count('$')
            features['nb_space'] = url.count(' ')

            # Special tokens
            features['nb_www'] = 1 if 'www' in domain.lower() else 0
            features['nb_com'] = 1 if '.com' in url.lower() else 0
            features['nb_dslash'] = url.count('//')
            features['http_in_path'] = 1 if 'http' in path.lower() else 0
            features['https_token'] = 1 if 'https' in url.lower() else 0

            # Ratios
            features['ratio_digits_url'] = len(re.findall(r'\d', url)) / len(url) if len(url) > 0 else 0
            features['ratio_digits_host'] = len(re.findall(r'\d', domain)) / len(domain) if len(domain) > 0 else 0

            # Punycode
            features['punycode'] = 1 if 'xn--' in domain else 0

            # Port check
            features['port'] = 1 if re.findall(r':[0-9]+', domain) else 0

            # TLD analysis
            features['tld_in_path'] = 1 if extract.suffix in path else 0
            features['tld_in_subdomain'] = 1 if extract.suffix in extract.subdomain else 0

            # Subdomain analysis
            features['abnormal_subdomain'] = 1 if len(domain.split('.')) > 3 else 0
            features['nb_subdomains'] = len(domain.split('.')) - 1

            # Additional suspicious patterns
            features['prefix_suffix'] = 1 if '-' in domain else 0
            features['random_domain'] = 1 if len(re.findall(r'[a-zA-Z0-9]+', domain.split('.')[0])[0]) > 20 else 0
            features['shortening_service'] = 1 if any(s in url.lower() for s in ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl']) else 0
            features['path_extension'] = 1 if re.search(r'\.(php|html?|aspx?|jsp|pdf)$', path.lower()) else 0

            # Add new security checks
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # SSL Check
            ssl_info = self.security_checker.check_ssl(domain)
            features['has_ssl'] = 1 if ssl_info['has_ssl'] else 0
            features['ssl_valid'] = 1 if ssl_info['valid'] else 0

            # DNS Records
            dns_records = self.security_checker.check_dns_records(domain)
            features['has_dns_records'] = 1 if any(dns_records.values()) else 0

            # WHOIS Information
            whois_info = self.security_checker.check_whois(domain)
            if whois_info.get('creation_date'):
                creation_date = whois_info['creation_date']
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                days_since_creation = (datetime.now() - creation_date).days
                features['domain_age_days'] = days_since_creation
            else:
                features['domain_age_days'] = 0

            # IP Reputation
            if features['ip']:
                ip_rep = self.security_checker.check_ip_reputation(domain)
                features['suspicious_ip_reputation'] = 1 if ip_rep.get('abuseConfidenceScore', 0) > 50 else 0
            else:
                features['suspicious_ip_reputation'] = 0

            # Reverse DNS
            if features['ip']:
                reverse_dns = self.security_checker.reverse_dns_lookup(domain)
                features['has_reverse_dns'] = 1 if reverse_dns else 0
            else:
                features['has_reverse_dns'] = 1

            return features

        except Exception as e:
            print(f"Error extracting features: {str(e)}")
            return self._get_default_features()

    def _get_default_features(self):
        return {feature: 0 for feature in self.features_list}

    def train_model(self, data_path):
        try:
            print("Loading dataset...")
            df = pd.read_csv(data_path)
            
            print("Preparing features...")
            X = df[self.features_list]
            y = df['status']
            
            print("Splitting dataset...")
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            
            print("Training model...")
            self.classifier.fit(X_train, y_train)
            
            print("Evaluating model...")
            y_pred = self.classifier.predict(X_test)
            print("\nClassification Report:")
            print(classification_report(y_test, y_pred))
            
            # Save the model
            self.save_model()
            print("Model saved successfully!")


            
        except Exception as e:
            print(f"Error in training: {str(e)}")

    def predict_url(self, url):
        try:
            # Extract domain from URL
            parsed = urlparse(url)
            domain = parsed.netloc
            base_domain = '.'.join(domain.split('.')[-2:])  # Get base domain
            
            # Check if domain is trusted
            if base_domain in self.trusted_domains:
                return {
                    'status': 'legitimate',
                    'confidence': 0.95,
                    'features': self.extract_features(url),
                    'analysis': 'Domain is verified and trusted'
                }
            
            # Extract features and make prediction
            features = self.extract_features(url)
            features_df = pd.DataFrame([features])
            
            # Ensure all features are present
            for feature in self.features_list:
                if feature not in features_df.columns:
                    features_df[feature] = 0
            
            features_df = features_df[self.features_list]
            
            # Calculate security score
            security_score = self._calculate_security_score(features)
            
            # Make prediction with classifier
            prediction = self.classifier.predict(features_df)[0]
            probabilities = self.classifier.predict_proba(features_df)[0]
            confidence = float(max(probabilities))
            
            # Adjust prediction based on security score
            final_status = self._determine_final_status(prediction, confidence, security_score, features)
            
            # Generate analysis
            analysis = self._generate_analysis(features)
            
            return {
                'status': final_status['status'],
                'confidence': final_status['confidence'],
                'features': features,
                'analysis': analysis
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': str(e),
                'features': self._get_default_features(),
                'analysis': f"Error during analysis: {str(e)}"
            }

    def _calculate_security_score(self, features):
        score = 1.0
        
        # Major positive indicators
        if features['has_ssl'] and features['ssl_valid']:
            score *= 1.2
        if features['domain_age_days'] > 365:
            score *= 1.15
        if features['has_dns_records']:
            score *= 1.1
        
        # Major negative indicators
        if features['suspicious_ip_reputation']:
            score *= 0.6
        if features['shortening_service']:
            score *= 0.7
        if features['domain_age_days'] < 30:
            score *= 0.8
        
        # Normalize score between 0 and 1
        return min(max(score, 0), 1)

    def _determine_final_status(self, prediction, confidence, security_score, features):
        # High security score overrides prediction
        if security_score > 0.8:
            return {
                'status': 'legitimate',
                'confidence': max(confidence, security_score)
            }
        
        # Known security risks
        if features['suspicious_ip_reputation'] or features['shortening_service']:
            return {
                'status': 'malicious',
                'confidence': max(confidence, 0.8)
            }
        
        # Default to classifier prediction with adjusted confidence
        adjusted_confidence = (confidence + security_score) / 2
        return {
            'status': prediction,
            'confidence': adjusted_confidence
        }

    def _generate_analysis(self, features):
        analysis = []
        
        # URL Structure Analysis
        if features['length_url'] > 75:
            analysis.append("Warning: URL is unusually long")
        if features['nb_subdomains'] > 3:
            analysis.append("Warning: Multiple subdomains detected")
        
        # Suspicious Characters
        if features['nb_at'] > 0:
            analysis.append("Warning: URL contains @ symbol")
        if features['nb_percent'] > 0:
            analysis.append("Warning: URL contains encoded characters")
        
        # Security Indicators
        if features['ip']:
            analysis.append("Warning: IP address used instead of domain name")
        if not features['https_token']:
            analysis.append("Warning: No HTTPS detected")
        if features['port']:
            analysis.append("Warning: Unusual port number in URL")
        if features['punycode']:
            analysis.append("Warning: Punycode encoding detected")
        
        # Suspicious Patterns
        if features['shortening_service']:
            analysis.append("Warning: URL shortening service detected")
        if features['random_domain']:
            analysis.append("Warning: Random-looking domain detected")
        if features['prefix_suffix']:
            analysis.append("Warning: Hyphens in domain name")

        # Add new security analysis
        if not features['has_ssl']:
            analysis.append("Warning: No SSL certificate found")
        if not features['ssl_valid']:
            analysis.append("Warning: Invalid SSL certificate")
        if not features['has_dns_records']:
            analysis.append("Warning: Missing DNS records")
        if features['domain_age_days'] < 30:
            analysis.append("Warning: Domain is less than 30 days old")
        if features['suspicious_ip_reputation']:
            analysis.append("Warning: IP address has poor reputation")
        if not features['has_reverse_dns']:
            analysis.append("Warning: No reverse DNS record found")
        
        return ' '.join(analysis)

    def save_model(self):
        model_data = {
            'classifier': self.classifier,
            'features_list': self.features_list
        }
        joblib.dump(model_data, 'url_detector_model.joblib')

    def load_model(self):
        try:
            model_data = joblib.load('url_detector_model.joblib')
            self.classifier = model_data['classifier']
            self.features_list = model_data['features_list']
            print("Model loaded successfully!")
        except Exception as e:
            print(f"Error loading model: {str(e)}")