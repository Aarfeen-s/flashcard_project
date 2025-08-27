
document.addEventListener('DOMContentLoaded', function() {
    let questionIndex = 0;
    let questions = [];

    const prevButton = document.getElementById('prev-question-btn');
    const nextButton = document.getElementById('next-question-btn');
    const viewAnswerButton = document.getElementById('view-answer-btn');

    // Fetch questions from the backend
    fetch('/questions/')  // Assuming '/questions/' is the endpoint for fetching questions
        .then(response => response.json())
        .then(data => {
            questions = data;
            showQuestion();
        });

    function showQuestion() {
        const question = questions[questionIndex];
        document.getElementById('question').textContent = question.ques_text;
        document.getElementById('answer').textContent = question.answers;
        document.getElementById('answer').style.display = 'none';
        prevButton.style.display = questionIndex === 0 ? 'none' : 'block';
        nextButton.style.display = questionIndex === questions.length - 1 ? 'none' : 'block';
        viewAnswerButton.style.display = question.answers ? 'block' : 'none';
    }

    document.getElementById('view-answer-btn').addEventListener('click', function() {
        document.getElementById('answer').style.display = 'block';
        this.style.display = 'none';
    });

    prevButton.addEventListener('click', function() {
        questionIndex--;
        showQuestion();
    });

    nextButton.addEventListener('click', function() {
        questionIndex++;
        showQuestion();
    });
});