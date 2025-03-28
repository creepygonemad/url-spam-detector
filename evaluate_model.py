import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, roc_curve, auc, precision_recall_curve
import matplotlib.pyplot as plt
import seaborn as sns
from model import URLDetector
import os

def evaluate_model():
    # Initialize the model
    print("Loading model...")
    detector = URLDetector()
    detector.load_model()

    # Load the test dataset
    print("Loading test dataset...")
    test_data = pd.read_csv(os.path.join('data', 'malicious_urls.csv'))
    
    # Get predictions
    predictions = []
    confidence_scores = []
    features_list = []
    
    # Map the labels: 'phishing' -> 1, 'legitimate' -> 0
    label_map = {'phishing': 1, 'legitimate': 0}
    true_labels = [label_map[status] for status in test_data['status']]  # Changed from 'label' to 'status'
    
    print("Making predictions...")
    for i, url in enumerate(test_data['url']):
        if i % 100 == 0:  # Progress indicator
            print(f"Processing URL {i+1}/{len(test_data)}")
            
        result = detector.predict_url(url)
        
        # Map prediction status to binary values
        if result['status'] in ['malicious', 'phishing']:
            predictions.append(1)
        else:
            predictions.append(0)
        confidence_scores.append(result['confidence'])
        features_list.append(result['features'])
    
    # Create results directory if it doesn't exist
    results_dir = os.path.join('static', 'evaluation_results')
    os.makedirs(results_dir, exist_ok=True)
    
    # Print and save classification report
    print("\nClassification Report:")
    report = classification_report(true_labels, predictions, 
                                 target_names=['Legitimate', 'Malicious'])
    print(report)
    
    with open(os.path.join(results_dir, 'classification_report.txt'), 'w') as f:
        f.write(report)
    
    # Create confusion matrix
    plt.figure(figsize=(10, 8))
    cm = confusion_matrix(true_labels, predictions)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Legitimate', 'Malicious'],
                yticklabels=['Legitimate', 'Malicious'])
    plt.title('Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.savefig(os.path.join(results_dir, 'confusion_matrix.png'))
    plt.close()
    
    # Create ROC curve
    fpr, tpr, _ = roc_curve(true_labels, confidence_scores)
    roc_auc = auc(fpr, tpr)
    
    plt.figure(figsize=(10, 8))
    plt.plot(fpr, tpr, color='darkorange', lw=2,
             label=f'ROC curve (AUC = {roc_auc:.3f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic (ROC) Curve')
    plt.legend(loc="lower right")
    plt.grid(True)
    plt.savefig(os.path.join(results_dir, 'roc_curve.png'))
    plt.close()
    
    # Create precision-recall curve
    precision, recall, _ = precision_recall_curve(true_labels, confidence_scores)
    pr_auc = auc(recall, precision)
    
    plt.figure(figsize=(10, 8))
    plt.plot(recall, precision, color='blue', lw=2,
             label=f'PR curve (AUC = {pr_auc:.3f})')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title('Precision-Recall Curve')
    plt.legend(loc="lower left")
    plt.grid(True)
    plt.savefig(os.path.join(results_dir, 'precision_recall_curve.png'))
    plt.close()
    
    # Feature importance analysis
    features_df = pd.DataFrame(features_list)
    feature_correlations = features_df.corr()['suspicious_ip_reputation'].sort_values(ascending=False)
    
    plt.figure(figsize=(12, 8))
    feature_correlations.plot(kind='bar')
    plt.title('Feature Correlations with Malicious URLs')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(os.path.join(results_dir, 'feature_importance.png'))
    plt.close()
    
    # Calculate and return performance metrics
    return {
        'auc_score': roc_auc,
        'pr_auc_score': pr_auc,
        'total_samples': len(true_labels),
        'malicious_samples': sum(true_labels),
        'legitimate_samples': len(true_labels) - sum(true_labels),
        'accuracy': sum(np.array(true_labels) == np.array(predictions)) / len(true_labels),
        'feature_importance': feature_correlations.to_dict()
    }

if __name__ == '__main__':
    print("Starting URL Detector Model Evaluation...")
    try:
        metrics = evaluate_model()
        print("\nEvaluation Results:")
        print(f"Total URLs analyzed: {metrics['total_samples']}")
        print(f"Legitimate URLs: {metrics['legitimate_samples']}")
        print(f"Malicious URLs: {metrics['malicious_samples']}")
        print(f"Model Accuracy: {metrics['accuracy']:.3f}")
        print(f"ROC AUC Score: {metrics['auc_score']:.3f}")
        print(f"PR AUC Score: {metrics['pr_auc_score']:.3f}")
        print("\nDetailed results have been saved in static/evaluation_results/")
    except Exception as e:
        print(f"Error during evaluation: {str(e)}")
