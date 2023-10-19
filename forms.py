from flask_wtf import FlaskForm
# from flask import Markup
from wtforms import StringField, PasswordField, BooleanField, SubmitField, RadioField, SelectField
from wtforms.validators import DataRequired, InputRequired 
from wtforms import widgets
from wtforms.widgets import html_params
from markupsafe import escape, Markup


class SelectMod(widgets.Select):
    @classmethod
    def render_option(cls, value, label, selected, **kwargs):
        if value is True:
            # Handle the special case of a 'True' value.
            # THIS IS GONNA THROW AN ERROR
            # text_type is not defined
            value = text_type(value)

        options = dict(kwargs, value=value)
        print(f"Value: {value}, Label: {label}, Selected: {selected}")
        if value == -1:
            options['disabled'] = True
            options['selected'] = True
            options['value'] = ''

        if selected:
            options['selected'] = True
        return Markup('<option %s>%s</option>' % (html_params(**options), escape(label)))

class SelectFieldWithDisabledFirstChoice(SelectField):
    widget = SelectMod()
#     def __init__(self, *args, **kwargs):
#         super(SelectFieldWithDisabledFirstChoice, self).__init__(*args, **kwargs)
#         self.choices = [('', 'Select an option')] + self.choices


class LoginForm(FlaskForm):
    prolific_pid = StringField('Prolific PID', validators=[DataRequired()])
    study_id = StringField('Study ID', validators=[DataRequired()])
    session_id = StringField('Session ID', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')


class SurveyForm(FlaskForm):
    eng_label = Markup('<strong>Engagingness:</strong> Given the context, is the model-generated response <em>engaging</em>?')
    rel_label = Markup('<strong>Relevance:</strong> Given the context, is the model-generated response <em>relevant</em>?')
    flu_label = Markup('<strong>Fluency:</strong> Given the context, is the model-generated response <em>fluent</em>?')
    coh_label = Markup('<strong>Coherence:</strong> Given the context, is the model-generated response <em>coherent</em>?')
    q1 = SelectFieldWithDisabledFirstChoice(eng_label, 
                    choices=[(-1, "-- please select an answer from this list --"), 
                             (0, 'No (ends conversation, irrelevant, or not engaging)'),
                             (1, 'Somewhat (not engaging, but relevant and/or continues conversation)'), 
                             (2, 'Yes (engaging, relevant, and continues conversation)')],
                    description="Engaging: The response can be followed-up on by the user.", 
                    validators=[DataRequired()])

    q2 = SelectFieldWithDisabledFirstChoice(rel_label, 
                     choices=[(-1, "-- please select an answer from this list --"), 
                              (0, 'No'), 
                              (1, 'Somewhat'), 
                              (2, 'Yes')], 
                     description='Relevant: Response is on topic and a valid/reasonable continuation of the conversation.', 
                     validators=[DataRequired()])

    q3 = SelectFieldWithDisabledFirstChoice(flu_label, 
                     choices=[(-1, "-- please select an answer from this list --"), 
                              (0, 'No'), 
                              (1, 'Somewhat'), 
                              (2, 'Yes')], 
                     description='Fluent: Response follows all the rules of English grammar.', 
                     validators=[DataRequired()])

    q4 = SelectFieldWithDisabledFirstChoice(coh_label, 
                     choices=[(-1, "-- please select an answer from this list --"), 
                              (0, 'No'), 
                              (1, 'Somewhat'), 
                              (2, 'Yes')], 
                     description='Coherent: The response is logically connected and easy to understand in the context of the conversation. It presents a clear and organized train of thought.', 
                     validators=[DataRequired()])
    hidden_timestamp_start = StringField('hidden_timestamp_start', validators=[DataRequired()], default=0)
    hidden_timestamp_end = StringField('hidden_timestamp_end', validators=[DataRequired()], default=0)
    submit = SubmitField('Submit')

