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
        # print(f"Value: {value}, Label: {label}, Selected: {selected}")
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

    q1_choices = [(-1, "-- please select an answer from this list --"), 
                             (0, 'No (ends conversation, irrelevant, or not engaging)'),
                             (1, 'Somewhat (not engaging, but relevant and/or continues conversation)'), 
                             (2, 'Yes (engaging, relevant, and continues conversation)')]

    q2_choices = [(-1, "-- please select an answer from this list --"), 
                              (0, 'No'), 
                              (1, 'Somewhat'), 
                              (2, 'Yes')]

    q3_choices =[(-1, "-- please select an answer from this list --"), 
                              (0, 'No'), 
                              (1, 'Somewhat'), 
                              (2, 'Yes')]
    q4_choices = [(-1, "-- please select an answer from this list --"), 
                              (0, 'No'), 
                              (1, 'Somewhat'), 
                              (2, 'Yes')]

    engaging_descrip = Markup('The response can be followed-up on by the user.')
    relevant_descrip = Markup('Response is on topic and a valid/reasonable continuation of the conversation.')
    fluent_descrip = Markup('Response follows all the rules of English grammar.')
    coherent_descrip = Markup('The response is logically connected and easy to understand in the context of the conversation. It presents a clear and organized train of thought.')

    q1_a = SelectFieldWithDisabledFirstChoice(eng_label, choices=q1_choices, description = engaging_descrip, validators=[DataRequired()])
    q2_a = SelectFieldWithDisabledFirstChoice(rel_label, choices=q2_choices, description = relevant_descrip, validators=[DataRequired()])
    q3_a = SelectFieldWithDisabledFirstChoice(flu_label, choices=q3_choices, description = fluent_descrip, validators=[DataRequired()])
    q4_a = SelectFieldWithDisabledFirstChoice(coh_label, choices=q4_choices, description = coherent_descrip, validators=[DataRequired()])


    q1_b = SelectFieldWithDisabledFirstChoice(eng_label, choices=q1_choices, description = engaging_descrip, validators=[DataRequired()])
    q2_b = SelectFieldWithDisabledFirstChoice(rel_label, choices=q2_choices, description = relevant_descrip, validators=[DataRequired()])
    q3_b = SelectFieldWithDisabledFirstChoice(flu_label, choices=q3_choices, description = fluent_descrip, validators=[DataRequired()])
    q4_b = SelectFieldWithDisabledFirstChoice(coh_label, choices=q4_choices, description = coherent_descrip, validators=[DataRequired()])

    question_id = StringField('Question ID', validators=[DataRequired()])
    hidden_timestamp_start = StringField('hidden_timestamp_start', validators=[DataRequired()], default=0)
    hidden_timestamp_end = StringField('hidden_timestamp_end', validators=[DataRequired()], default=0)
    submit = SubmitField('Submit')