from setuptools import setup, find_packages

setup(
    name="packetsense",
    version="0.1.0",
    description="AI-powered network traffic analyzer",
    author="Your Name",
    packages=find_packages(),
    install_requires=[
        "streamlit==1.29.0",
        "pyshark==0.6",
        "openai==1.3.0",
        "pandas==2.1.4",
        "plotly==5.17.0",
        "python-dotenv==1.0.0"
    ],
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)