from setuptools import setup, find_packages

setup(
    name="phishing_detection_api",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "fastapi",
        "uvicorn",
        "tensorflow-cpu",
        "pydantic",
        "scikit-learn"
    ],
    author="Quang Nguyen",
    description="AI Phishing URL Detection System"
)