from flask import Blueprint, jsonify, request
from honeyshield.backend.models import db, DecoyAsset
from honeyshield.backend.llm_decoy import decoy_generator
import logging

logger = logging.getLogger(__name__)

decoy_bp = Blueprint("decoy", __name__, url_prefix="/api/decoy")

@decoy_bp.route("/generate", methods=["POST"])
def generate_decoy():
    """
    Generate a new decoy of a specific type.
    """
    data = request.get_json(force=True, silent=True) or {}
    decoy_type = data.get("type")

    if not decoy_type:
        return jsonify({"error": "Missing decoy type"}), 400

    # Call Featherless GLM-5
    result = decoy_generator.generate_decoy(decoy_type)
    
    if "error" in result:
        return jsonify({"error": result["error"]}), 500

    # Save to db
    asset = DecoyAsset.query.filter_by(decoy_type=decoy_type).first()
    if not asset:
        asset = DecoyAsset(decoy_type=decoy_type)
        db.session.add(asset)
    
    asset.content = result
    db.session.commit()

    return jsonify({"status": "success", "data": asset.to_dict()}), 200


@decoy_bp.route("/list", methods=["GET"])
def list_decoys():
    """
    List all generated decoys.
    """
    assets = DecoyAsset.query.all()
    # Return as key-value pairs
    result = {a.decoy_type: a.content for a in assets}
    return jsonify(result), 200
