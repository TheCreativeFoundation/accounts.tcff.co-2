import os
import boto3
import json
import sys
import firebase_admin
# import sendgrid
# import time
# from sendgrid.helpers.mail import Email, Substitution, Mail, Personalization
# from python_http_client import exceptions
from firebase_admin import credentials, auth, firestore
from flask import Flask, render_template, request, redirect, jsonify
from dotenv import load_dotenv

# from raven.contrib.flask import Sentry
# sentry = Sentry(app, dsn='https://8ae50a1ca8954cb8881024c1a21c1a4e:73f6e2336f7549f1b016834297276ca3@sentry.io/1251762')

application = Flask(__name__)

load_dotenv(override=True)

aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")

if not os.path.isfile("key.json"):
    session = boto3.session.Session(
        aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key
    )
    session.resource("s3").Bucket("tcf-accounts-key").download_file(
        "key.json", "key.json"
    )

cred = credentials.Certificate("key.json")

try:
    firebase_admin.initialize_app(cred)
except Exception as e:
    print(e)

db = firestore.client()

# sg = sendgrid.SendGridAPIClient(apikey=os.getenv("SENDGRID_API_KEY"))

# ------------ API EXTENSION ------------ #


@application.route("/api/verify-token", methods=["POST"])
def api_verify_token():
    token = request.form.get("token")
    if not token:
        return jsonify({"statusCode": 406, "message": "missing id token: " + str(e)})
    try:
        decoded_token: dict = auth.verify_id_token(token)
    except Exception as e:
        return jsonify({"statusCode": 505, "message": "critical error: " + str(e)})
    else:
        if decoded_token.get("uid"):
            return jsonify(
                {
                    "statusCode": 202,
                    "message": "operation successful",
                    "uid": decoded_token.get("uid"),
                }
            )
        return jsonify({"statusCode": 505, "message": "critical error: " + str(e)})


@application.route("/api/set-claims", methods=["POST"])
def set_claims():
    try:
        token = request.form["token"]
    except KeyError as e:
        return jsonify({"statusCode": 406, "message": "KeyError Exception" + str(e)})
    except Exception as e:
        return jsonify({"statusCode": 505, "message": "critical error: " + str(e)})
    else:
        try:
            decoded_token: dict = auth.verify_id_token(token)
        except Exception as e:
            return jsonify({"statusCode": 505, "message": "Exception" + str(e)})
        else:
            try:
                uid = decoded_token["uid"]
            except KeyError as e:
                return jsonify(
                    {"statusCode": 406, "message": "KeyError Exception" + str(e)}
                )
            except Exception as e:
                return jsonify({"statusCode": 505, "message": "Exception" + str(e)})
            else:
                try:
                    doc_data: dict = db.collection("accounts").document(
                        uid
                    ).get().to_dict()
                except TypeError as e:
                    return jsonify(
                        {"statusCode": 406, "message": "TypeError Exception" + str(e)}
                    )
                except Exception as e:
                    return jsonify({"statusCode": 505, "message": "Exception" + str(e)})
                else:
                    try:
                        permissions: dict = doc_data["permissions"]
                    except TypeError as e:
                        return jsonify(
                            {
                                "statusCode": 406,
                                "message": "TypeError Exception" + str(e),
                            }
                        )
                    except KeyError as e:
                        return jsonify(
                            {
                                "statusCode": 406,
                                "message": "KeyError Exception" + str(e),
                            }
                        )
                    except Exception as e:
                        return jsonify(
                            {"statusCode": 505, "message": "Exception" + str(e)}
                        )
                    else:
                        try:
                            auth.set_custom_user_claims(uid, permissions)
                        except Exception as e:
                            return jsonify(
                                {"statusCode": 505, "message": "Exception" + str(e)}
                            )
                        else:
                            return jsonify(
                                {"statusCode": 202, "message": "operation successful"}
                            )


# ------------ URL ROUTES ------------ #


@application.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@application.route("/error", methods=["GET"])
def error():
    return render_template("error.html")


@application.route("/signin", methods=["GET"])
def signin():
    if not request.args.get("callback_uri"):
        return redirect("/", code=302)
    return render_template("signin.html")


@application.route("/signin/confirm", methods=["GET"])
def confirm():
    if not request.args.get("callback_uri"):
        return redirect("/", code=302)
    return render_template("confirm.html")


@application.route("/signin/forgotpassword", methods=["GET"])
def forgot_password():
    if not request.args.get("callback_uri"):
        return redirect("/error", code=302)
    return render_template("forgotpassword.html")


@application.route("/signup", methods=["GET"])
def signup():
    if not request.args.get("callback_uri"):
        return redirect("/", code=302)
    return render_template("signup.html")


@application.route("/myaccount/mngt", methods=["GET"])
def account_management():
    if not request.args.get("mode"):
        return redirect("/myaccount", code=302)
    else:
        code = request.args.get("oobCode")
        continue_url = request.args.get("continueUrl")
        if not code or not continue_url:
            return redirect("/error", code=404)
        else:
            if request.args["mode"] == "resetPassword":
                return render_template("resetpassword.html")
            elif request.args["mode"] == "verifyEmail":
                return render_template("verifyemail.html")
            else:
                return redirect("/error", code=302)


@application.route("/createtoken", methods=["POST"])
def create_user_token():
    try:
        token = request.form["token"]
    except KeyError as e:
        return jsonify({"statusCode": 407, "message": "token missing"})
    else:
        try:
            decoded_token: dict = auth.verify_id_token(token)
        except Exception as e:
            return jsonify({"statusCode": 505, "message": "Exception" + str(e)})
        else:
            try:
                uid = decoded_token["uid"]
            except KeyError as e:
                return jsonify(
                    {"statusCode": 406, "message": "KeyError Exception" + str(e)}
                )
            except Exception as e:
                return jsonify({"statusCode": 505, "message": "Exception" + str(e)})
            else:
                try:
                    doc_data: dict = db.collection("accounts").document(
                        uid
                    ).get().to_dict()
                except TypeError as e:
                    return jsonify(
                        {"statusCode": 406, "message": "TypeError Exception" + str(e)}
                    )
                except Exception as e:
                    return jsonify({"statusCode": 505, "message": "Exception" + str(e)})
                else:
                    try:
                        permissions: dict = doc_data["permissions"]
                    except KeyError as e:
                        return jsonify(
                            {
                                "statusCode": 406,
                                "message": "KeyError Exception" + str(e),
                            }
                        )
                    except TypeError as e:
                        return jsonify(
                            {
                                "statusCode": 406,
                                "message": "TypeError Exception" + str(e),
                            }
                        )
                    except Exception as e:
                        return jsonify(
                            {"statusCode": 505, "message": "Exception" + str(e)}
                        )
                    else:
                        try:
                            custom_token = auth.create_custom_token(uid, permissions)
                        except Exception as e:
                            return jsonify(
                                {"statusCode": 505, "message": "Exception" + str(e)}
                            )
                        else:
                            return jsonify(
                                {
                                    "statusCode": 202,
                                    "message": "operation was successful",
                                    "token": str(custom_token),
                                }
                            )

@application.route("/email/<email_type>", methods=["POST"])
def email(email_type):
    return jsonify({"statusCode": 202, "message": "email sent correctly"})

# @application.route("/email/<email_type>", methods=["POST"])
# def email(email_type: str):
#     token = request.form.get("token")
#     if not token:
#         return jsonify({"statusCode": 407, "message": "token missing"})
#     try:
#         decoded_token: dict = auth.verify_id_token(token)
#     except Exception as e:
#         return jsonify({"statusCode": 505, "message": "Exception" + str(e)})
#     else:
#         try:
#             personalization = Personalization()
#             personalization.add_to(Email(decoded_token.get("email")))
#             mail = Mail()
#             mail.from_email = Email("jojo@tcff.co")
#             mail.subject = "I'm replacing the subject tag"
#             mail.add_personalization(personalization)
#             if email_type == "newuser":
#                 mail.template_id = "d-26b95c7042cc4294bc5c8df58f07de56"
#             elif email_type == "passwordreset":
#                 mail.template_id = "d-6710abfa23f541f988ee3063f146ccf9"
#             elif email_type == "onconfirm":
#                 mail.template_id = "d-81dadc44b09d44e4a577b1dd2127a0a6"
#             else:
#                 return jsonify({"statusCode": 404, "message": "email type not found"})
#         except Exception as e:
#             return jsonify({"statusCode": 505, "message": "Exception" + str(e)})
#         else:
#             try:
#                 sg.client.mail.send.post(request_body=mail.get())
#             except exceptions.BadRequestsError as e:
#                 return jsonify(
#                     {
#                         "statusCode": 505,
#                         "message": "couldnt send email => Exception" + str(e),
#                     }
#                 )
#             else:
#                 return jsonify({"statusCode": 202, "message": "email sent correctly"})


if __name__ == "__main__":
    if sys.platform == "win32":
        application.run(host="127.0.0.1", port=5000, debug=True)
    application.run()
