from flask import Flask, render_template, request, jsonify, url_for
from model import URLDetector
import traceback
import os

app = Flask(__name__, static_folder='static')
detector = URLDetector()

def initialize_model():
    model_path = 'url_detector_model.joblib'
    dataset_path = os.path.join('data', 'malicious_urls.csv')

    try:
        # Check if model file exists
        if os.path.exists(model_path):
            print("Loading existing model...")
            detector.load_model()
            print("Model loaded successfully!")
        else:
            print("No existing model found. Training new model...")
            # Check if dataset exists
            if not os.path.exists(dataset_path):
                raise FileNotFoundError(f"Dataset not found at {dataset_path}")
            
            print("Training model with dataset:", dataset_path)
            detector.train_model(dataset_path)
            print("Model training completed and saved!")

    except Exception as e:
        print(f"Error during model initialization: {str(e)}")
        print(traceback.format_exc())
        raise Exception("Failed to initialize model")

# Initialize model at startup
print("Initializing URL Detector...")
initialize_model()
print("Initialization complete!")

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check_url', methods=['POST'])
def check_url():
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'error': 'No data provided',
                'message': 'Request body is empty'
            }), 400

        url = data.get('url', '').strip()
        if not url:
            return jsonify({
                'error': 'No URL provided',
                'message': 'URL field is empty'
            }), 400

        # Basic URL validation
        if not url.startswith(('http://', 'https://')):
            return jsonify({
                'error': 'Invalid URL format',
                'message': 'URL must start with http:// or https://'
            }), 400

        # Get prediction
        result = detector.predict_url(url)
        
        # Map confidence to user-friendly status
        if result['status'] == 'legitimate' and result['confidence'] >= 0.8:
            result['status'] = 'safe'
        elif result['status'] == 'malicious' or result['confidence'] < 0.6:
            result['status'] = 'dangerous'
        else:
            result['status'] = 'suspicious'
            
        print(f"Analysis for {url}:", result)
        return jsonify(result)

    except Exception as e:
        print("Error during URL analysis:")
        print(traceback.format_exc())
        return jsonify({
            'error': 'Analysis failed',
            'message': str(e)
        }), 500



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)