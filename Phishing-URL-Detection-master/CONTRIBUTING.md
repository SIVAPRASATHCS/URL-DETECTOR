# Contributing to Phishing URL Detection Tool

🎉 Thank you for considering contributing to our phishing URL detection project! Your contributions help make the internet safer for everyone.

## 🌟 Ways to Contribute

### 🐛 **Report Bugs**
- Use the [GitHub Issues](https://github.com/SIVAPRASATHCS/URL-DETECTOR/issues) page
- Provide detailed information about the bug
- Include steps to reproduce the issue
- Add screenshots if applicable

### ✨ **Suggest Features**
- Open a [Feature Request](https://github.com/SIVAPRASATHCS/URL-DETECTOR/issues/new)
- Describe the feature and its benefits
- Explain how it would improve the project

### 🔧 **Code Contributions**
- Fork the repository
- Create a feature branch
- Make your changes
- Submit a pull request

## 🚀 **Getting Started**

### **Setup Development Environment**
```bash
# Clone your fork
git clone https://github.com/yourusername/URL-DETECTOR.git
cd URL-DETECTOR

# Install dependencies
pip install -r deploy_requirements.txt

# Install development dependencies
pip install pytest black flake8 mypy

# Run the application
python -m uvicorn enhanced_main:app --reload
```

### **Development Workflow**
1. **Create a branch** for your feature
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write clean, readable code
   - Add comments for complex logic
   - Follow existing code style

3. **Test your changes**
   ```bash
   # Run tests
   pytest

   # Check code style
   black .
   flake8 .
   ```

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "Add: your descriptive commit message"
   ```

5. **Push and create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

## 📝 **Code Style Guidelines**

### **Python Code**
- Follow [PEP 8](https://pep8.org/) style guide
- Use meaningful variable and function names
- Add docstrings to functions and classes
- Keep functions small and focused

### **Documentation**
- Update README.md if needed
- Add comments for complex algorithms
- Include examples in docstrings

### **Commit Messages**
- Use clear, descriptive commit messages
- Start with a verb (Add, Fix, Update, Remove)
- Keep the first line under 50 characters

## 🧪 **Testing**

### **Running Tests**
```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_feature_extractor.py

# Run with coverage
pytest --cov=.
```

### **Writing Tests**
- Add tests for new features
- Test edge cases and error conditions
- Use descriptive test names

## 📋 **Pull Request Process**

### **Before Submitting**
- [ ] Tests pass locally
- [ ] Code follows style guidelines
- [ ] Documentation is updated
- [ ] Commit messages are clear

### **PR Description Template**
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement

## Testing
- [ ] Tests pass
- [ ] New tests added (if applicable)

## Screenshots (if applicable)
Add screenshots of UI changes
```

## 🔍 **Areas for Contribution**

### **🎯 High Priority**
- Improve ML model accuracy
- Add new URL feature extraction methods
- Enhance web interface usability
- Add comprehensive test coverage

### **📚 Documentation**
- API documentation improvements
- Usage examples and tutorials
- Deployment guides for new platforms
- Translation to other languages

### **🛡️ Security**
- Security vulnerability fixes
- Rate limiting improvements
- Input validation enhancements
- Privacy protection features

### **⚡ Performance**
- Optimize URL analysis speed
- Reduce memory usage
- Database query optimization
- Caching improvements

## 🤝 **Community Guidelines**

### **Be Respectful**
- Be welcoming to newcomers
- Provide constructive feedback
- Respect different opinions and approaches

### **Be Helpful**
- Help others learn and contribute
- Share knowledge and resources
- Collaborate openly

### **Be Professional**
- Keep discussions focused on the project
- Avoid off-topic conversations
- Maintain a positive environment

## 🆘 **Getting Help**

### **Need Help?**
- Check existing [Issues](https://github.com/SIVAPRASATHCS/URL-DETECTOR/issues)
- Start a [Discussion](https://github.com/SIVAPRASATHCS/URL-DETECTOR/discussions)
- Contact maintainers via GitHub

### **Resources**
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [scikit-learn User Guide](https://scikit-learn.org/stable/user_guide.html)
- [Python Style Guide](https://pep8.org/)

## 🏆 **Recognition**

Contributors will be:
- Listed in the project contributors
- Mentioned in release notes
- Credited in documentation

## 📞 **Contact**

- **GitHub:** [@SIVAPRASATHCS](https://github.com/SIVAPRASATHCS)
- **Project Issues:** [GitHub Issues](https://github.com/SIVAPRASATHCS/URL-DETECTOR/issues)

---

**Thank you for helping make the internet safer! 🛡️🌐**